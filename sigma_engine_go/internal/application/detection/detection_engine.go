package detection

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/edr-platform/sigma-engine/pkg/ports"
)

// Note: SigmaDetectionEngine implements the ports.DetectionEngine interface
// with the following exceptions for backward compatibility:
// - LoadRules uses []*domain.SigmaRule instead of []ports.Rule
// This is intentional to maintain compatibility with existing code.

// QualityConfig controls detection quality to reduce false positives in production.
type QualityConfig struct {
	// MinConfidence is the minimum confidence required for a detection result to be returned.
	// Typical production default: 0.6 (60%).
	MinConfidence float64

	// EnableFilters controls whether "filter*" selections suppress detections even if the
	// Sigma condition did not explicitly include "and not filter".
	EnableFilters bool

	// EnableContextValidation enables extra context-based scoring (parent process/user/path).
	// When enabled, confidence may be reduced for missing/weak context.
	EnableContextValidation bool

	// Filtering enables global whitelisting to suppress common legitimate activity.
	Filtering FilteringConfig

	// RuleQuality enables rule-level load filtering.
	RuleQuality RuleQualityConfig
}

// FilteringConfig defines global whitelisting patterns.
type FilteringConfig struct {
	Enabled bool

	WhitelistedProcesses       []string
	WhitelistedUsers           []string
	WhitelistedParentProcesses []string
}

// RuleQualityConfig controls which rules are considered production-quality.
type RuleQualityConfig struct {
	MinLevel         string
	AllowedStatus    []string
	SkipExperimental bool
}

// SigmaDetectionEngine is the core detection engine that matches events against Sigma rules.
// Thread-safe and optimized for high-throughput event processing.
type SigmaDetectionEngine struct {
	rules          []*domain.SigmaRule
	compiled       map[*domain.SigmaRule]*compiledRule
	ruleIndex      *rules.RuleIndexer
	modifierEngine *ModifierRegistry
	fieldMapper    *mapping.FieldMapper
	stats          *DetectionStats
	quality        QualityConfig
	mu             sync.RWMutex

	exceptions *ExceptionManager
	suppressed atomic.Uint64 // matches hidden by detection exceptions
}

// SetExceptionManager installs analyst-managed detection exceptions.
func (e *SigmaDetectionEngine) SetExceptionManager(m *ExceptionManager) { e.exceptions = m }

// SuppressedByExceptions returns how many rule matches exceptions hid.
func (e *SigmaDetectionEngine) SuppressedByExceptions() uint64 { return e.suppressed.Load() }

// NewSigmaDetectionEngine creates a new detection engine.
//
// fieldCache is accepted for API compatibility but no longer used: field
// resolution is memoised per event (see eventContext), which is faster and
// cannot leak values between events.
func NewSigmaDetectionEngine(
	fieldMapper *mapping.FieldMapper,
	modifierEngine *ModifierRegistry,
	fieldCache *cache.FieldResolutionCache,
	quality QualityConfig,
) *SigmaDetectionEngine {
	_ = fieldCache

	// Normalize defaults defensively
	if quality.MinConfidence <= 0 {
		quality.MinConfidence = 0.6
	}

	return &SigmaDetectionEngine{
		compiled:       make(map[*domain.SigmaRule]*compiledRule),
		modifierEngine: modifierEngine,
		fieldMapper:    fieldMapper,
		stats:          NewDetectionStats(),
		ruleIndex:      rules.NewRuleIndexer(),
		quality:        quality,
	}
}

// maxRejectWarnings bounds per-rule warning logs during a load; the rest are
// summarised so a large rule set cannot flood the log.
const maxRejectWarnings = 25

// compileRules compiles rules, returning the usable ones and logging every
// rejection reason (first maxRejectWarnings individually, then a summary).
func compileRules(in []*domain.SigmaRule) ([]*domain.SigmaRule, map[*domain.SigmaRule]*compiledRule, int) {
	ok := make([]*domain.SigmaRule, 0, len(in))
	compiled := make(map[*domain.SigmaRule]*compiledRule, len(in))
	rejected := 0
	for _, rule := range in {
		if rule == nil {
			continue
		}
		cr, err := compileRule(rule)
		if err != nil {
			rejected++
			if rejected <= maxRejectWarnings {
				logger.Warnf("Rule rejected (not loaded) %s %q: %v", rule.ID, rule.Title, err)
			} else {
				logger.Debugf("Rule rejected (not loaded) %s %q: %v", rule.ID, rule.Title, err)
			}
			continue
		}
		ok = append(ok, rule)
		compiled[rule] = cr
	}
	return ok, compiled, rejected
}

// LoadRules compiles rules, replaces the active rule set and rebuilds the
// index. Quality filtering (status, level, experimental) is performed by the
// RuleLoader; rules with unsupported or invalid constructs are rejected here.
func (e *SigmaDetectionEngine) LoadRules(rules []*domain.SigmaRule) error {
	usable, compiled, rejected := compileRules(rules)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = usable
	e.compiled = compiled
	e.ruleIndex.BuildIndex(usable)

	if rejected > 0 {
		logger.Warnf("Loaded %d rules into detection engine; %d rejected as invalid/unsupported (see warnings above)", len(usable), rejected)
	} else {
		logger.Infof("Loaded %d rules into detection engine", len(usable))
	}
	return nil
}

func ValidateRule(rule *domain.SigmaRule) error {
	if rule == nil {
		return fmt.Errorf("nil rule")
	}
	if err := rule.Validate(); err != nil {
		return err
	}
	_, err := compileRule(rule)
	return err
}

// TestRule evaluates a separate snapshot using the actual matching pipeline.
// It cannot change live rules, exception hits, persisted alerts or responses.
func (e *SigmaDetectionEngine) TestRule(rule *domain.SigmaRule, event *domain.LogEvent) ([]*domain.DetectionResult, error) {
	if err := ValidateRule(rule); err != nil {
		return nil, err
	}
	e.mu.RLock()
	test := NewSigmaDetectionEngine(e.fieldMapper, e.modifierEngine, nil, e.quality)
	e.mu.RUnlock()
	if err := test.LoadRules([]*domain.SigmaRule{rule}); err != nil {
		return nil, err
	}
	return test.Detect(event), nil
}

// Detect evaluates an event against all loaded rules and returns matching results.
// Thread-safe and optimized for performance (< 1ms target per event).
func (e *SigmaDetectionEngine) Detect(event *domain.LogEvent) []*domain.DetectionResult {
	start := time.Now()
	e.stats.RecordEvent()

	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []*domain.DetectionResult

	// Defense-in-depth: drop events whose parent process is the EDR agent
	// itself. The agent applies its own self-exclusion in the collector, but
	// this guard ensures any event that slips through (older agents, future
	// regressions, alternate ingestion paths) cannot generate self-alerts.
	if isAgentSelfEvent(event) {
		e.stats.RecordProcessingTime(time.Since(start))
		return nil
	}

	// Global whitelist suppression (reduces false positives on common legitimate activity)
	if e.isWhitelistedEvent(event) {
		// Treat as processed with no detections.
		e.stats.RecordProcessingTime(time.Since(start))
		return nil
	}

	// Step 1: Get candidate rules by logsource (O(1) lookup)
	candidates := e.getCandidateRules(event)
	e.stats.RecordCandidateCount(len(candidates))
	ec := newEventContext(event, e.fieldMapper)

	// Step 2: Evaluate each candidate rule
	for _, rule := range candidates {
		result := e.evaluateRule(rule, event, ec)
		if result != nil {
			results = append(results, result)
			e.stats.RecordDetection(true)
		}
		e.stats.RecordRuleEvaluation(rule.ID, result != nil)
	}

	// Step 3: Update statistics
	duration := time.Since(start)
	e.stats.RecordProcessingTime(duration)

	if len(results) > 0 {
		logger.Debugf("Event %s matched %d rules in %v", getEventIDString(event), len(results), duration)
	}

	return results
}

// DetectBatch processes multiple events and returns aggregated results.
func (e *SigmaDetectionEngine) DetectBatch(events []*domain.LogEvent) *domain.BatchDetectionResult {
	start := time.Now()

	var allResults []*domain.DetectionResult
	matchedCount := 0

	for _, event := range events {
		results := e.Detect(event)
		if len(results) > 0 {
			allResults = append(allResults, results...)
			matchedCount++
		}
	}

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1e6

	return &domain.BatchDetectionResult{
		Results:       allResults,
		TotalEvents:   len(events),
		TotalMatches:  matchedCount,
		ElapsedTimeMS: elapsedMs,
	}
}

// =============================================================================
// ATOMIC EVENT AGGREGATION
// =============================================================================

// DetectAggregated evaluates an event against ALL candidate rules and returns
// a single EventMatchResult containing ALL matches.
//
// This is the key method for reducing alert fatigue:
//   - Old behavior (Detect): 1 event + 5 matching rules → 5 separate alerts
//   - New behavior (DetectAggregated): 1 event + 5 matching rules → 1 aggregated alert
//
// Thread-safe and optimized for performance.
func (e *SigmaDetectionEngine) DetectAggregated(event *domain.LogEvent) *domain.EventMatchResult {
	start := time.Now()
	e.stats.RecordEvent()

	e.mu.RLock()
	defer e.mu.RUnlock()

	result := domain.NewEventMatchResult(event)

	// Defense-in-depth: drop events generated by the EDR agent itself
	// (parent_executable == agent path). See isAgentSelfEvent for details.
	if isAgentSelfEvent(event) {
		e.stats.RecordProcessingTime(time.Since(start))
		return result // Empty result (no matches)
	}

	// Global whitelist suppression
	if e.isWhitelistedEvent(event) {
		e.stats.RecordProcessingTime(time.Since(start))
		return result // Empty result (no matches)
	}

	// Step 1: Get ALL candidate rules by logsource (O(1) lookup)
	candidates := e.getCandidateRules(event)
	e.stats.RecordCandidateCount(len(candidates))
	ec := newEventContext(event, e.fieldMapper)

	// Step 2: Evaluate EVERY candidate rule and collect ALL matches
	matchCount := 0
	for _, rule := range candidates {
		match := e.evaluateRuleForAggregation(rule, event, ec)
		if match != nil {
			result.AddMatch(match.Rule, match.Confidence, match.MatchedFields, match.MatchedSelections)
			e.stats.RecordDetection(true)
			matchCount++
		}
		e.stats.RecordRuleEvaluation(rule.ID, match != nil)
	}

	// Step 3: Record timing
	duration := time.Since(start)
	result.EvaluationTimeMS = float64(duration.Nanoseconds()) / 1e6
	e.stats.RecordProcessingTime(duration)

	// Sampled diagnostic log (every 5000 events) for debugging
	evtCount := e.stats.TotalEvents()
	if evtCount%5000 == 1 {
		cmdLine := event.GetStringField("data.command_line")
		executable := event.GetStringField("data.executable")
		name := event.GetStringField("data.name")
		logger.Infof("🔍 DIAG [evt#%d] cat=%s prod=%s svc=%s | candidates=%d matches=%d | cmdline=%q executable=%q name=%q",
			evtCount, event.Category, event.Product, event.Service,
			len(candidates), matchCount,
			truncate(cmdLine, 80), truncate(executable, 80), truncate(name, 40))
	}

	return result
}

// evaluateRuleForAggregation evaluates a single rule and returns a RuleMatch if matched.
func (e *SigmaDetectionEngine) evaluateRuleForAggregation(
	rule *domain.SigmaRule,
	event *domain.LogEvent,
	ec *eventContext,
) *domain.RuleMatch {
	m := e.matchRule(rule, event, ec)
	if m == nil {
		return nil
	}
	return &domain.RuleMatch{
		Rule:              rule,
		Confidence:        m.confidence,
		MatchedFields:     m.matchedFields,
		MatchedSelections: m.matchedSelections,
	}
}

// getCandidateRules returns every rule whose logsource fits the event: its
// primary and parent categories plus its service (memoised in the index).
func (e *SigmaDetectionEngine) getCandidateRules(event *domain.LogEvent) []*domain.SigmaRule {
	cats := event.Categories
	if len(cats) == 0 {
		cats = domain.ExpandCategories(event.Category)
	}
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = string(c)
	}
	return e.ruleIndex.GetCandidateRules(event.Product, names, event.Service)
}

// evaluateRule evaluates a single rule against an event.
// Returns DetectionResult if rule matches, nil otherwise.
func (e *SigmaDetectionEngine) evaluateRule(
	rule *domain.SigmaRule,
	event *domain.LogEvent,
	ec *eventContext,
) *domain.DetectionResult {
	m := e.matchRule(rule, event, ec)
	if m == nil {
		return nil
	}
	return &domain.DetectionResult{
		Rule:              rule,
		Event:             event,
		Matched:           true,
		Confidence:        m.confidence,
		MatchedSelections: m.matchedSelections,
		MatchedFields:     m.matchedFields,
		Timestamp:         time.Now(),
	}
}

// ruleMatch is the engine-level result of a successful rule evaluation.
type ruleMatch struct {
	confidence        float64
	matchedFields     map[string]interface{}
	matchedSelections []string
}

// matchRule is the single evaluation path shared by Detect and
// DetectAggregated:
//  1. evaluate the compiled selections and the pre-parsed condition
//     (the condition is authoritative for every selection it references);
//  2. apply filter* selections the condition does not reference, when
//     EnableFilters is on;
//  3. score context quality and gate on it (MinConfidence);
//  4. report confidence = rule-level prior × context quality.
func (e *SigmaDetectionEngine) matchRule(rule *domain.SigmaRule, event *domain.LogEvent, ec *eventContext) *ruleMatch {
	cr := e.compiled[rule]
	if cr == nil {
		return nil // not compiled (rejected at load) — never evaluated
	}
	out := cr.evaluate(ec, e.quality.EnableFilters)
	if out == nil {
		return nil
	}

	quality := 1.0
	if e.quality.EnableContextValidation {
		quality = e.validateContext(cr, ec)
	}
	if quality < e.quality.MinConfidence {
		logger.Debugf("Context-quality gate DROP: rule=%s quality=%.3f < min=%.3f", rule.ID, quality, e.quality.MinConfidence)
		return nil
	}
	confidence := math.Min(getLevelConfidence(rule.Level)*quality, 1.0)

	// Analyst-approved exceptions (known-benign activity for this rule).
	if e.exceptions.suppresses(rule, event, ec) {
		e.suppressed.Add(1)
		return nil
	}

	// Enrich output with decoded payloads (e.g., PowerShell -EncodedCommand) so the
	// SOC sees the real script/command even when only base64 is logged.
	enrichMatchedFieldsWithDecodedPayload(event, out.matchedFields)

	return &ruleMatch{
		confidence:        confidence,
		matchedFields:     out.matchedFields,
		matchedSelections: out.matchedSelections,
	}
}

// validateContext scores (0,1] how complete the event context is for this
// rule: it is reduced when the rule tests parent / command-line / user
// fields that the event does not carry (they were only in branches that did
// not decide the match). It never blocks a match by itself; the
// MinConfidence gate decides.
func (e *SigmaDetectionEngine) validateContext(cr *compiledRule, ec *eventContext) float64 {
	score := 1.0
	if cr.needsParent && !ec.resolve("ParentImage").present {
		score *= 0.8
	}
	if cr.needsCmd && !ec.resolve("CommandLine").present {
		score *= 0.85
	}
	if cr.needsUser && !ec.resolve("User").present {
		score *= 0.9
	}
	return score
}

func (e *SigmaDetectionEngine) getStringField(event *domain.LogEvent, fieldName string) (string, bool) {
	if event == nil {
		return "", false
	}
	v, _, err := e.fieldMapper.ResolveField(event.RawData, fieldName)
	if err != nil || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if ok && strings.TrimSpace(s) != "" {
		return s, true
	}
	// Fallback: stringify
	str := strings.TrimSpace(toString(v))
	if str == "" {
		return "", false
	}
	return str, true
}

// isWhitelistedEvent returns true if the event matches any configured whitelist rule.
// Whitelisting is evaluated before rule matching to reduce false positives and CPU load.
//
// NOTE (RC-2 fix): User and ParentImage whitelisting have been removed.
//   - User whitelist (e.g. "NT AUTHORITY\SYSTEM") was far too broad: it silently
//     dropped the vast majority of Windows process events before Sigma rules could
//     evaluate them, creating massive detection blind spots.
//   - ParentImage whitelist (e.g. explorer.exe, services.exe) suppressed events
//     for legitimate attacker parent processes (many tools are spawned by explorer
//     or services). Sigma rules themselves contain fine-grained filter selections
//     that handle false positive suppression per-rule.
func (e *SigmaDetectionEngine) isWhitelistedEvent(event *domain.LogEvent) bool {
	if !e.quality.Filtering.Enabled || event == nil {
		return false
	}

	// Process image whitelist only (exact binary paths like svchost.exe, lsass.exe)
	if image, ok := e.getStringField(event, "Image"); ok {
		if matchAnyPathPattern(image, e.quality.Filtering.WhitelistedProcesses) {
			return true
		}
	}

	return false
}

// matchAnyPathPattern returns true if `path` matches any of the whitelist
// patterns. This is a pure-string implementation that works identically on
// Linux (Docker) and Windows, unlike filepath.Match/filepath.Clean which
// interpret backslashes differently across platforms.
//
// Supported pattern syntax:
//   - Leading `*\` or `*\\` — suffix match ("ends with").
//   - Trailing `*`           — prefix match ("starts with").
//   - No wildcards            — exact match.
func matchAnyPathPattern(path string, patterns []string) bool {
	if path == "" || len(patterns) == 0 {
		return false
	}
	// Normalize: lowercase + unify separators to backslash for Windows paths
	normalized := strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pLower := strings.ToLower(strings.ReplaceAll(p, "/", "\\"))

		// Wildcard at both ends: *text* — contains
		if strings.HasPrefix(pLower, "*") && strings.HasSuffix(pLower, "*") {
			core := strings.Trim(pLower, "*")
			if core != "" && strings.Contains(normalized, core) {
				return true
			}
			continue
		}

		// Leading wildcard: *\thing.exe — suffix / ends-with
		if strings.HasPrefix(pLower, "*") {
			suffix := pLower[1:] // strip leading *
			if strings.HasSuffix(normalized, suffix) {
				return true
			}
			continue
		}

		// Trailing wildcard: C:\Program Files\Microsoft* — prefix / starts-with
		if strings.HasSuffix(pLower, "*") {
			prefix := pLower[:len(pLower)-1] // strip trailing *
			if strings.HasPrefix(normalized, prefix) {
				return true
			}
			continue
		}

		// Exact match (no wildcards)
		if normalized == pLower {
			return true
		}
	}
	return false
}

func levelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "informational", "info":
		return 0
	default:
		// Unknown levels are treated as medium-ish to avoid dropping potentially relevant rules.
		return 2
	}
}

// getLevelConfidence maps Sigma rule level to base detection confidence.
//
// Calibration methodology: Bayesian prior probability P(attack | rule_match).
// Values derived from the SigmaHQ rule taxonomy and empirical FPR data:
//   - critical: Near-zero FP rate rules → 0.95 (strong prior, but not 1.0
//     per Cromwell's Rule: no prior probability should be 0 or 1 because
//     no update by Bayes' theorem can then revise it)
//   - high:     Confirmed low-FP rules → 0.85
//   - medium:   Moderate FP potential  → 0.65
//   - low:      High FP potential      → 0.45
//   - informational: Observational     → 0.25
//
// Reference: SigmaHQ Rule Specification v2, Bayesian epistemology (Cromwell's Rule)
func getLevelConfidence(level string) float64 {
	switch level {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.65
	case "low":
		return 0.45
	case "informational":
		return 0.25
	default:
		return 0.50
	}
}

// getMatchedSelectionNames returns names of selections that matched.
func getMatchedSelectionNames(selectionResults map[string]bool) []string {
	var matched []string
	for name, isMatched := range selectionResults {
		if isMatched {
			matched = append(matched, name)
		}
	}
	return matched
}

// isFilterSelection checks if a selection name indicates a filter (negation).
func isFilterSelection(name string) bool {
	return len(name) >= 6 && name[:6] == "filter"
}

// getEventIDString returns event ID as string.
func getEventIDString(event *domain.LogEvent) string {
	if event.EventID != nil {
		return *event.EventID
	}
	return "unknown"
}

// Stats returns detection statistics snapshot.
func (e *SigmaDetectionEngine) Stats() *DetectionStatsSnapshot {
	return e.stats.Snapshot()
}

// ResetStats resets all statistics.
func (e *SigmaDetectionEngine) ResetStats() {
	e.stats.Reset()
}

// =============================================================================
// PORTS INTERFACE IMPLEMENTATION
// =============================================================================

// Match implements ports.DetectionEngine.Match
// Evaluates a single event against all loaded rules and returns MatchResult.
func (e *SigmaDetectionEngine) Match(ctx context.Context, event ports.Event) (*ports.MatchResult, error) {
	start := time.Now()

	// Convert ports.Event to domain.LogEvent
	logEvent, ok := event.(*domain.LogEvent)
	if !ok {
		return nil, nil // Incompatible event type
	}

	// Use existing detection method
	results := e.Detect(logEvent)

	// Convert to ports.MatchResult
	matches := make([]ports.RuleMatch, 0, len(results))
	for _, r := range results {
		matches = append(matches, ports.RuleMatch{
			RuleID:          r.Rule.ID,
			RuleTitle:       r.Rule.Title,
			Severity:        r.Rule.Level,
			Confidence:      r.Confidence,
			MatchedFields:   r.MatchedFields,
			MITRETechniques: r.Rule.MITRETechniques(),
			Tags:            r.Rule.Tags,
		})
	}

	return &ports.MatchResult{
		EventID:        logEvent.ComputeHash(),
		Matched:        len(matches) > 0,
		MatchCount:     len(matches),
		Matches:        matches,
		EvaluatedRules: e.RuleCount(),
		LatencyMs:      float64(time.Since(start).Nanoseconds()) / 1e6,
		Timestamp:      time.Now(),
	}, nil
}

// MatchBatch implements ports.DetectionEngine.MatchBatch
// Processes multiple events efficiently.
func (e *SigmaDetectionEngine) MatchBatch(ctx context.Context, events []ports.Event) (*ports.BatchMatchResult, error) {
	start := time.Now()

	results := make([]ports.MatchResult, 0, len(events))
	matchedEvents := 0
	totalMatches := 0

	var minLatency, maxLatency, totalLatency float64
	minLatency = math.MaxFloat64

	for _, event := range events {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := e.Match(ctx, event)
		if err != nil {
			continue
		}
		if result == nil {
			continue
		}

		results = append(results, *result)

		if result.Matched {
			matchedEvents++
			totalMatches += result.MatchCount
		}

		totalLatency += result.LatencyMs
		if result.LatencyMs < minLatency {
			minLatency = result.LatencyMs
		}
		if result.LatencyMs > maxLatency {
			maxLatency = result.LatencyMs
		}
	}

	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Nanoseconds()) / 1e6

	avgLatency := 0.0
	if len(results) > 0 {
		avgLatency = totalLatency / float64(len(results))
	}
	if minLatency == math.MaxFloat64 {
		minLatency = 0
	}

	throughput := 0.0
	if elapsed.Seconds() > 0 {
		throughput = float64(len(events)) / elapsed.Seconds()
	}

	return &ports.BatchMatchResult{
		TotalEvents:   len(events),
		MatchedEvents: matchedEvents,
		TotalMatches:  totalMatches,
		Results:       results,
		Stats: ports.BatchStats{
			TotalTimeMs:   elapsedMs,
			AvgLatencyMs:  avgLatency,
			MaxLatencyMs:  maxLatency,
			MinLatencyMs:  minLatency,
			ThroughputEPS: throughput,
		},
	}, nil
}

// AddRules implements ports.DetectionEngine.AddRules
// Adds rules without replacing existing ones.
func (e *SigmaDetectionEngine) AddRules(ctx context.Context, newRules []ports.Rule) error {
	candidates := make([]*domain.SigmaRule, 0, len(newRules))
	for _, r := range newRules {
		if domainRule, ok := r.(*domain.SigmaRule); ok {
			candidates = append(candidates, domainRule)
		}
	}
	usable, compiled, rejected := compileRules(candidates)

	e.mu.Lock()
	defer e.mu.Unlock()

	added := 0
	for _, rule := range usable {
		duplicate := false
		for _, existing := range e.rules {
			if existing.ID == rule.ID {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue // already loaded; skip without aborting the batch
		}
		if err := e.ruleIndex.AddRule(rule); err != nil {
			logger.Warnf("Rule %s not added to index: %v", rule.ID, err)
			continue
		}
		e.rules = append(e.rules, rule)
		e.compiled[rule] = compiled[rule]
		added++
	}

	logger.Infof("Added %d rules (%d rejected as invalid), total now: %d", added, rejected, len(e.rules))
	if rejected > 0 {
		return fmt.Errorf("%d rule(s) rejected as invalid or unsupported", rejected)
	}
	return nil
}

// RemoveRule implements ports.DetectionEngine.RemoveRule
// Removes a single rule by ID.
func (e *SigmaDetectionEngine) RemoveRule(ctx context.Context, ruleID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	found := false
	newRules := make([]*domain.SigmaRule, 0, len(e.rules))
	for _, rule := range e.rules {
		if rule.ID == ruleID {
			found = true
			delete(e.compiled, rule)
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		return nil // Rule not found, no error
	}

	e.rules = newRules
	e.ruleIndex.RemoveRule(ruleID)

	logger.Infof("Removed rule %s, total now: %d", ruleID, len(e.rules))
	return nil
}

// GetRules implements ports.DetectionEngine.GetRules
// Returns rules matching the filter.
func (e *SigmaDetectionEngine) GetRules(ctx context.Context, filter ports.RuleFilter) ([]ports.Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]ports.Rule, 0)

	for _, rule := range e.rules {
		// Apply filters
		if filter.Product != "" && (rule.LogSource.Product == nil || *rule.LogSource.Product != filter.Product) {
			continue
		}
		if filter.Category != "" && (rule.LogSource.Category == nil || *rule.LogSource.Category != filter.Category) {
			continue
		}
		if filter.Level != "" && rule.Level != filter.Level {
			continue
		}
		if filter.Status != "" && rule.Status != filter.Status {
			continue
		}

		// Check IDs filter
		if len(filter.IDs) > 0 {
			found := false
			for _, id := range filter.IDs {
				if rule.ID == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check tags filter (rule must have ALL specified tags)
		if len(filter.Tags) > 0 {
			hasAllTags := true
			for _, tag := range filter.Tags {
				found := false
				for _, ruleTag := range rule.Tags {
					if ruleTag == tag {
						found = true
						break
					}
				}
				if !found {
					hasAllTags = false
					break
				}
			}
			if !hasAllTags {
				continue
			}
		}

		result = append(result, rule)
	}

	return result, nil
}

// RuleCount implements ports.DetectionEngine.RuleCount
func (e *SigmaDetectionEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Health implements ports.DetectionEngine.Health
// Returns engine health status.
func (e *SigmaDetectionEngine) Health() *ports.EngineHealth {
	status := ports.HealthStatusHealthy
	// Degrade health if we've had panics (panic count tracked in processor stats)
	// For now, just report healthy since we don't track panics at engine level

	return &ports.EngineHealth{
		Status:    status,
		IsHealthy: status == ports.HealthStatusHealthy,
		CheckedAt: time.Now(),
	}
}

// Shutdown implements ports.DetectionEngine.Shutdown
// Gracefully stops the engine.
func (e *SigmaDetectionEngine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear rules to prevent new detections
	e.rules = nil
	e.ruleIndex = rules.NewRuleIndexer()

	logger.Info("Detection engine shutdown complete")
	return nil
}

// PortsStats returns stats in the ports.EngineStats format.
func (e *SigmaDetectionEngine) PortsStats() *ports.EngineStats {
	snapshot := e.stats.Snapshot()

	return &ports.EngineStats{
		LoadedRules:     e.RuleCount(),
		EventsProcessed: snapshot.TotalEvents,
		DetectionsFound: snapshot.TotalDetections,
		AvgLatencyMs:    float64(snapshot.AvgProcessingTime.Nanoseconds()) / 1e6,
		LastUpdated:     time.Now(),
	}
}

// truncate shortens a string to maxLen characters for log readability.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
