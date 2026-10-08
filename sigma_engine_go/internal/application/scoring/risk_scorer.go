// Package scoring provides the Context-Aware Risk Scoring engine for the
// EDR platform's Phase 1 detection enhancement.
//
// The scoring pipeline intercepts a matched EventMatchResult (after Sigma rule
// evaluation) and computes a dynamic risk_score (0–100) by aggregating five
// contextual signals:
//
//  1. Base Score      — derived from the Sigma rule's static severity
//  2. Lineage Bonus  — suspicious parent→child process relationships
//  3. Privilege Bonus — elevated/SYSTEM process context
//  4. Temporal Burst  — repeated firing of the same rule category in 5 min
//  5. FP Discount     — trusted/Microsoft signature reduces final score
//  6. UEBA Bonus/Discount — behavioral baseline anomaly/normalcy adjustment
//
// The ContextSnapshot struct captures the complete forensic picture at
// scoring time, which is stored in the PostgreSQL `context_snapshot` JSONB
// column in Sprint 3.
package scoring

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/edr-platform/sigma-engine/internal/domain"
	infracache "github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
)

// =============================================================================
// RiskScorer Interface
// =============================================================================

// ScoringInput bundles everything the RiskScorer needs to compute a score.
// Constructed by the caller (EventLoop or a future interceptor) and passed to Score().
type ScoringInput struct {
	// MatchResult is the output of DetectAggregated — mandatory.
	MatchResult *domain.EventMatchResult

	// Event is the raw LogEvent that triggered the match — mandatory.
	Event *domain.LogEvent

	// AgentID is the UUID of the reporting agent.
	// Derived from the event payload; used as the Redis cache partition key.
	AgentID string
}

// ScoringOutput is the result of a Score() call.
type ScoringOutput struct {
	// RiskScore is the final clamped risk score (0–100).
	RiskScore int

	// FalsePositiveRisk is a probability estimate (0.0–1.0) that this alert
	// is a false positive, based on signature status and known-good paths.
	// Stored in domain.Alert.FalsePositiveRisk in Sprint 3.
	FalsePositiveRisk float64

	// Snapshot is the full forensic evidence captured at scoring time.
	// Stored as JSONB in the alerts table in Sprint 3.
	Snapshot *ContextSnapshot
}

// RiskScorer is the interface for context-aware risk scoring.
// The production implementation is *DefaultRiskScorer.
// A stub (StaticRiskScorer) is provided for unit tests that don't need Redis.
type RiskScorer interface {
	// Score evaluates the contextual risk of a matched event and returns a
	// ScoringOutput. Score is safe for concurrent use by multiple goroutines.
	// Returns an error only for fatal infrastructure failures (e.g., burst
	// counter Redis error); a partial score is returned even on soft errors.
	Score(ctx context.Context, input ScoringInput) (*ScoringOutput, error)
}

// =============================================================================
// DefaultRiskScorer — Production Implementation
// =============================================================================

// DefaultRiskScorer is the full production risk scorer.
// It requires a LineageCache (for process ancestry), a BurstTracker
// (for temporal burst detection), and a BaselineProvider (for UEBA).
type DefaultRiskScorer struct {
	lineageCache     infracache.LineageCache
	burstTracker     BurstTracker
	matrix           *SuspicionMatrix
	baselineProvider baselines.BaselineProvider
	contextProvider  ContextPolicyProvider
	observed         ObservedCounter
	cfg              RiskScoringConfig
}

// ObservedCounter reports how many times a process started on an agent in
// the hour of `at` (implemented by baselines.BaselineAggregator).
type ObservedCounter interface {
	CurrentCount(agentID, processName string, at time.Time) int
}

// SetObservedCounter wires the current-hour execution counts used by UEBA.
func (rs *DefaultRiskScorer) SetObservedCounter(c ObservedCounter) { rs.observed = c }

// NewDefaultRiskScorer constructs the production risk scorer.
// baselineProvider may be baselines.NoopBaselineProvider{} for graceful degradation.
func NewDefaultRiskScorer(
	lineageCache infracache.LineageCache,
	burstTracker BurstTracker,
	baselineProvider baselines.BaselineProvider,
) *DefaultRiskScorer {
	return NewDefaultRiskScorerWithConfig(lineageCache, burstTracker, baselineProvider, DefaultRiskScoringConfig())
}

// NewDefaultRiskScorerWithConfig constructs the production risk scorer with an
// explicit tuning config (loaded from YAML). This is the preferred constructor
// for production so all constants are centrally managed.
func NewDefaultRiskScorerWithConfig(
	lineageCache infracache.LineageCache,
	burstTracker BurstTracker,
	baselineProvider baselines.BaselineProvider,
	cfg RiskScoringConfig,
) *DefaultRiskScorer {
	cfg.ValidateAndSetDefaults()
	return &DefaultRiskScorer{
		lineageCache:     lineageCache,
		burstTracker:     burstTracker,
		matrix:           NewSuspicionMatrix(),
		baselineProvider: baselineProvider,
		contextProvider:  NoopContextPolicyProvider{},
		cfg:              cfg,
	}
}

// SetContextPolicyProvider injects hybrid context-policy inputs (user/device/network).
func (rs *DefaultRiskScorer) SetContextPolicyProvider(provider ContextPolicyProvider) {
	if provider == nil {
		rs.contextProvider = NoopContextPolicyProvider{}
		return
	}
	rs.contextProvider = provider
}

// Score computes the risk score for a matched event.
//
// Formula (NIST SP 800-61 aligned, with non-linear interaction modeling):
//
//	risk_score = clamp(
//	    baseScore(severity, matchCount)
//	  + lineageBonus(parentChain)
//	  + privilegeBonus(eventData)
//	  + burstBonus(agentID, ruleCategory)
//	  + uebaAnomalyBonus(agentID, processName, hourOfDay)
//	  + interactionBonus(lineage, privilege, ueba)     // non-linear cross-dimension signal
//	  - fpDiscount(signatureStatus, executablePath)
//	  - uebaNormalcyDiscount(agentID, processName, hourOfDay)
//	, 0, 100)
func (rs *DefaultRiskScorer) Score(ctx context.Context, input ScoringInput) (*ScoringOutput, error) {
	if input.MatchResult == nil || input.Event == nil {
		return &ScoringOutput{RiskScore: 0, Snapshot: &ContextSnapshot{}}, nil
	}

	// ── Step 1: Base Score ─────────────────────────────────────────────────────
	primary := input.MatchResult.HighestSeverityMatch()
	if primary == nil || primary.Rule == nil {
		return &ScoringOutput{RiskScore: 0, Snapshot: &ContextSnapshot{}}, nil
	}

	matchCount := input.MatchResult.MatchCount()
	baseScore := computeBaseScore(primary.Rule.Severity(), matchCount, rs.cfg.BaseScore)

	// ── Step 2: Lineage Bonus ─────────────────────────────────────────────────
	pid := extractInt64(input.Event.RawData, "pid")
	lineageChain, lineageErr := rs.lineageCache.GetLineageChain(ctx, input.AgentID, pid)
	if lineageErr != nil {
		// Non-fatal: score without lineage context
		lineageErr = fmt.Errorf("lineage lookup: %w", lineageErr)
	}

	// ── DIAGNOSTIC LOG ────────────────────────────────────────────────────────
	agentPfx := input.AgentID
	if len(agentPfx) > 8 {
		agentPfx = agentPfx[:8]
	}
	if lineageErr != nil {
		logger.Debugf("[SCORER] pid=%d agent=%s chainLen=0 err=%v", pid, agentPfx, lineageErr)
	} else {
		logger.Debugf("[SCORER] pid=%d agent=%s chainLen=%d", pid, agentPfx, len(lineageChain))
	}
	// ─────────────────────────────────────────────────────────────
	lineageBonus, lineageSuspicion := rs.matrix.ComputeBonus(lineageChain)

	// ── Step 3: Privilege Bonus ───────────────────────────────────────────────
	privilegeBonus := computePrivilegeBonus(input.Event.RawData, rs.cfg.Privilege)

	// ── Step 4: Temporal Burst Bonus ─────────────────────────────────────────
	// Distinct detections on this host within the window indicate attack
	// progression. One rule repeating (often a recurring benign task) does
	// not count — counting repeats amplified noisy false positives.
	burstCount, burstErr := rs.burstTracker.DistinctRules(ctx, input.AgentID, primary.Rule.ID)
	if burstErr != nil {
		burstErr = fmt.Errorf("burst tracker: %w", burstErr)
	}
	burstBonus := computeBurstBonus(burstCount, rs.cfg.Burst)

	// ── Step 5: False-Positive Discount ──────────────────────────────────────
	sigStatus := extractString(input.Event.RawData, "signature_status")
	executable := extractString(input.Event.RawData, "executable")
	fpDiscount := computeFPDiscount(sigStatus, executable, rs.cfg.FalsePositive)
	fpRisk := computeFPRisk(sigStatus, executable, rs.cfg.FalsePositive)
	// Dual-use system binaries (LOLBins: powershell, rundll32, mshta, ...)
	// are Microsoft-signed by definition and are exactly what many rules
	// target; their signature says nothing about benign use.
	if isDualUseBinary(executable) {
		fpDiscount = 0
		if fpRisk > rs.cfg.FalsePositive.RiskUnknownOrMissingSig {
			fpRisk = rs.cfg.FalsePositive.RiskUnknownOrMissingSig
		}
	}
	// Lineage override: a Microsoft-signed binary spawned by a suspicious
	// parent (e.g. powershell.exe from winword.exe) is an attack, not a FP.
	// Cap FP risk at 0.25 when lineage suspicion is critical so the FP risk
	// value does not suppress genuinely malicious signed binaries.
	if lineageSuspicion == "critical" && fpRisk > 0.25 {
		fpRisk = 0.25
	}

	// ── Step 5.5: UEBA Behavioral Baseline Adjustment ────────────────────────
	// Query the in-memory baseline cache to determine if this process is:
	//   a) Anomalous: running at an hour it has never been seen (+15)
	//   b) Normal: running within 1 standard deviation of its baseline (-10)
	// The adjustment is confidence-weighted: it only kicks in when the model
	// has ≥ 0.30 confidence (≈3 days of observations) to avoid false signals
	// on brand-new agents.
	processName := extractString(input.Event.RawData, "name")
	eventAt := baselines.EventTime(input.Event.RawData)
	if eventAt.IsZero() {
		eventAt = time.Now().UTC()
	}
	uebaBonus, uebaDiscount, uebaSignal, uebaReason, uebaErr := rs.computeUEBA(ctx, input.AgentID, processName, eventAt)
	if uebaErr != nil {
		uebaErr = fmt.Errorf("ueba baseline: %w", uebaErr)
	}

	// ── Step 5.6: Non-Linear Interaction Bonus ───────────────────────────────
	// NIST SP 800-61 / MITRE ATT&CK aligned: when multiple high-severity
	// contextual signals co-occur, the combined risk is greater than the sum
	// of its parts. This captures cross-dimensional attack patterns that no
	// single signal alone would warrant escalation.
	interactionBonus := computeInteractionBonus(lineageBonus, privilegeBonus, uebaBonus, burstBonus, rs.cfg.Interaction)

	// ── Step 5.7: Hybrid Context Policy Factors (user/device/network) ───────
	userName := extractString(input.Event.RawData, "user_name")
	sourceIP := extractString(input.Event.RawData, "ip_address")
	if sourceIP == "" {
		sourceIP = extractString(input.Event.RawData, "source.ip_address")
	}
	contextFactors, contextErr := rs.contextProvider.Resolve(ctx, input.AgentID, userName, sourceIP)
	if contextErr != nil {
		contextErr = fmt.Errorf("context policy provider: %w", contextErr)
		contextFactors = DefaultContextFactors()
	}

	// ── Step 5.8: Context Quality Adjustment (best-practice uncertainty handling)
	// If ingestion could not collect all required context fields, avoid
	// overconfident scoring by applying a bounded quality factor.
	contextQualityScore := extractFloat64(input.Event.RawData, "context_quality_score")
	missingFields := extractStringSlice(input.Event.RawData, "missing_context_fields")
	qualityFactor := computeContextQualityFactor(contextQualityScore, len(missingFields), rs.cfg.Quality)

	// ── Step 6: Final Score ───────────────────────────────────────────────────
	raw := baseScore + lineageBonus + privilegeBonus + burstBonus + uebaBonus + interactionBonus - fpDiscount - uebaDiscount
	contextAdjusted := int(math.Round(float64(raw) * contextFactors.Multiplier(rs.cfg.ContextPolicy) * qualityFactor))
	finalScore := clamp(contextAdjusted, 0, 100)

	breakdown := ScoreBreakdown{
		BaseScore:               baseScore,
		LineageBonus:            lineageBonus,
		PrivilegeBonus:          privilegeBonus,
		BurstBonus:              burstBonus,
		FPDiscount:              fpDiscount,
		UEBABonus:               uebaBonus,
		UEBADiscount:            uebaDiscount,
		UEBASignal:              uebaSignal,
		UEBAReason:              uebaReason,
		InteractionBonus:        interactionBonus,
		UserRoleWeight:          contextFactors.UserRoleWeight,
		DeviceCriticalityWeight: contextFactors.DeviceCriticalityWeight,
		NetworkAnomalyFactor:    contextFactors.NetworkAnomalyFactor,
		ContextMultiplier:       contextFactors.Multiplier(rs.cfg.ContextPolicy),
		ContextQualityScore:     contextQualityScore,
		QualityFactor:           qualityFactor,
		ContextAdjustedScore:    contextAdjusted,
		RawScore:                raw,
		FinalScore:              finalScore,
	}

	// ── Step 7: Build Context Snapshot ───────────────────────────────────────
	snapshot := buildContextSnapshot(input, lineageChain, lineageSuspicion, burstCount, rs.cfg.Burst.WindowSec, breakdown)

	// Merge non-fatal errors into the snapshot (evidence of degraded context)
	if lineageErr != nil {
		snapshot.Warnings = append(snapshot.Warnings, lineageErr.Error())
	}
	if burstErr != nil {
		snapshot.Warnings = append(snapshot.Warnings, burstErr.Error())
	}
	if uebaErr != nil {
		snapshot.Warnings = append(snapshot.Warnings, uebaErr.Error())
	}
	if contextErr != nil {
		snapshot.Warnings = append(snapshot.Warnings, contextErr.Error())
	}

	snapshot.UserRoleWeight = contextFactors.UserRoleWeight
	snapshot.DeviceCriticalityWeight = contextFactors.DeviceCriticalityWeight
	snapshot.NetworkAnomalyFactor = contextFactors.NetworkAnomalyFactor
	snapshot.ContextMultiplier = contextFactors.Multiplier(rs.cfg.ContextPolicy)
	snapshot.ContextQualityScore = contextQualityScore
	snapshot.QualityFactor = qualityFactor
	snapshot.MissingContextFields = missingFields
	if len(missingFields) > 0 {
		snapshot.Warnings = append(snapshot.Warnings,
			fmt.Sprintf("partial context fields missing: %s", strings.Join(missingFields, ",")))
	}

	return &ScoringOutput{
		RiskScore:         finalScore,
		FalsePositiveRisk: fpRisk,
		Snapshot:          snapshot,
	}, nil
}

// =============================================================================
// UEBA Scoring Component
// =============================================================================

// uebaSignalType labels what the UEBA component determined.
const (
	UEBASignalNone    = "none"    // baseline not available / confidence too low
	UEBASignalAnomaly = "anomaly" // process running at first-seen hour or >3σ spike
	UEBASignalNormal  = "normal"  // process running within its expected baseline
)

// UEBA history requirements before any signal is produced: enough days of
// host activity and enough same-hour slots for a meaningful distribution.
const (
	uebaMinHostDays  = 7
	uebaSpikeMinRuns = 5
)

// computeUEBA compares the process with this host's baseline for the event's
// hour-of-day:
//   - anomaly: first time the process ever ran on the host, never ran at this
//     hour before, or the current-hour count exceeds mean + Zσ (and at least
//     uebaSpikeMinRuns, so tiny counts never qualify);
//   - normal:  the process routinely runs at this hour (present in at least
//     NormalAvgThreshold of the host's active slots) within mean + 1σ;
//   - none:    not enough history (learning) or no clear signal.
func (rs *DefaultRiskScorer) computeUEBA(
	ctx context.Context,
	agentID, processName string,
	at time.Time,
) (bonus, discount int, signal, reason string, err error) {
	if rs.baselineProvider == nil || processName == "" || agentID == "" {
		return 0, 0, UEBASignalNone, "", nil
	}
	b, err := rs.baselineProvider.Lookup(ctx, agentID, processName, at)
	if err != nil || b == nil {
		return 0, 0, UEBASignalNone, "", err
	}
	if b.HostObservedDays < uebaMinHostDays || b.ConfidenceScore < rs.cfg.UEBA.ConfidenceGate {
		return 0, 0, UEBASignalNone, fmt.Sprintf("baseline learning (%d day(s) of host history)", b.HostObservedDays), nil
	}
	hourStart := at.UTC().Truncate(time.Hour)
	if b.FirstSeenAt == nil || !b.FirstSeenAt.Before(hourStart) {
		return rs.cfg.UEBA.AnomalyBonus, 0, UEBASignalAnomaly,
			fmt.Sprintf("first time %s has run on this host (%d days observed)", processName, b.HostObservedDays), nil
	}
	if b.PresentSlots == 0 {
		return rs.cfg.UEBA.AnomalyBonus, 0, UEBASignalAnomaly,
			fmt.Sprintf("%s never ran at %02d:00 UTC on this host in %d active days", processName, b.HourOfDay, b.HostActiveSlots), nil
	}
	observed := 1
	if rs.observed != nil {
		if n := rs.observed.CurrentCount(agentID, processName, at); n > observed {
			observed = n
		}
	}
	mean, sd := b.AvgExecutionsPerHour, b.StddevExecutions
	if observed >= uebaSpikeMinRuns && float64(observed) > mean+rs.cfg.UEBA.ZScoreAnomalyThreshold*sd && float64(observed) > 2*mean {
		return rs.cfg.UEBA.AnomalyBonus, 0, UEBASignalAnomaly,
			fmt.Sprintf("%d runs this hour vs. typical %.1f ± %.1f", observed, mean, sd), nil
	}
	presence := float64(b.PresentSlots) / float64(b.HostActiveSlots)
	if presence >= rs.cfg.UEBA.NormalAvgThreshold && float64(observed) <= mean+math.Max(sd, 1) {
		return 0, rs.cfg.UEBA.NormalDiscount, UEBASignalNormal,
			fmt.Sprintf("%s routinely runs at this hour (%d of %d days)", processName, b.PresentSlots, b.HostActiveSlots), nil
	}
	return 0, 0, UEBASignalNone, "", nil
}

// =============================================================================
// Internal Scoring Functions
// =============================================================================

// computeBaseScore maps a Sigma severity level to an initial risk score,
// then applies a multi-rule bonus for correlated matches.
//
// Calibration reference: CVSS 3.1 Qualitative Severity Rating Scale (NIST NVD)
// adapted for EDR detection context. Unlike CVSS (which scores vulnerability
// exploitability), these scores represent initial detection suspicion BEFORE
// contextual enrichment. Values are set at ~70-90% of CVSS midpoints to
// leave headroom for additive bonuses (lineage, privilege, burst, UEBA,
// interaction) which can add up to +140 points total.
//
// Derivation (CVSS midpoint → EDR base score):
//
//	Informational:  0.0/10 →  10  (minimal detection signal, informational noise)
//	Low:       2.0/10 × 100 = 20, adjusted to 25 (margin for minimal context)
//	Medium:    5.45/10 × 100 = 55, set to 45 (leaves +55 headroom for bonuses)
//	High:      7.95/10 × 100 = 80, set to 65 (leaves +35 headroom for bonuses)
//	Critical:  9.5/10 × 100 = 95, set to 85 (leaves +15 for worst-case enrichment)
//
// Reference: NIST NVD CVSS v3.1 Specification §5 (Qualitative Severity Rating)
func computeBaseScore(severity domain.Severity, matchCount int, cfg BaseScoreConfig) int {
	var base int
	switch severity {
	case domain.SeverityInformational:
		base = cfg.Informational
	case domain.SeverityLow:
		base = cfg.Low
	case domain.SeverityMedium:
		base = cfg.Medium
	case domain.SeverityHigh:
		base = cfg.High
	case domain.SeverityCritical:
		base = cfg.Critical
	default:
		base = cfg.Unknown // unknown severity → configurable default
	}

	// Multi-rule correlation bonus: +5 per additional matched rule, capped at +15
	if matchCount > 1 {
		bonus := (matchCount - 1) * cfg.MatchCorrelationBonusPerRule
		if bonus > cfg.MatchCorrelationBonusCap {
			bonus = cfg.MatchCorrelationBonusCap
		}
		base += bonus
	}

	return base
}

// computePrivilegeBonus evaluates event-level privilege signals and returns
// a cumulative bonus to be added to the risk score.
//
// Industry alignment: NIST SP 800-53 AC-6 (Least Privilege) — processes
// running at elevated privilege levels in unexpected contexts are high-risk.
// The cumulative design stacks independent privilege indicators.
//
// Weight calibration (enterprise security standards):
//   - SYSTEM account:  +20 (highest privilege, rare for user-initiated activity)
//   - Admin SID (-500): +15 (built-in administrator, common privilege escalation target)
//   - System integrity: +15 (kernel-level integrity, should only be OS services)
//   - High + elevated:  +10 (UAC-bypassed admin context)
//   - Elevated token:   +10 (running above standard user)
//   - Unsigned binary:  +15 (no code-signing — highest abuse risk)
//   - Unknown signature: +8 (telemetry gap — moderate concern)
func computePrivilegeBonus(eventData map[string]interface{}, cfg PrivilegeConfig) int {
	bonus := 0

	userSID := extractString(eventData, "user_sid")
	integrityLevel := strings.ToLower(extractString(eventData, "integrity_level"))
	isElevated := extractBool(eventData, "is_elevated")
	sigStatus := strings.ToLower(extractString(eventData, "signature_status"))
	executable := strings.ToLower(extractString(eventData, "executable"))

	// SYSTEM account (Local System SID) — strongest signal
	// Legitimate processes rarely initiate suspicious activity as SYSTEM.
	if strings.HasPrefix(userSID, "S-1-5-18") { // NT AUTHORITY\SYSTEM
		bonus += cfg.BonusSystemSID
	} else if strings.HasSuffix(userSID, "-500") { // Built-in Administrator
		bonus += cfg.BonusAdminRID500
	}

	// Integrity level signals
	switch integrityLevel {
	case "system":
		// A SYSTEM token always carries System integrity: the same fact
		// must not be scored twice.
		if !strings.HasPrefix(userSID, "S-1-5-18") {
			bonus += cfg.BonusIntegritySys
		}
	case "high":
		if isElevated {
			bonus += cfg.BonusHighElevated // elevated admin doing something suspicious
		}
	}

	// Elevated token (applies even when integrity level is not "system")
	if isElevated && integrityLevel != "system" {
		bonus += cfg.BonusElevatedToken
	}

	// FIX ISSUE-02: Operator precedence bug.
	// Previously: `sigStatus == "unsigned" || sigStatus == "" && executable != ""`
	// Go evaluates this as: `unsigned || (empty && hasExe)` — meaning ANY
	// event with missing signature status AND an executable path got +15.
	// Now we explicitly distinguish:
	//   - "unsigned": confirmed unsigned binary → +15 (strong abuse indicator)
	//   - ""/unknown: telemetry gap, not the same as unsigned → +8 (moderate)
	if sigStatus == "unsigned" {
		bonus += cfg.BonusUnsignedBinary // Confirmed unsigned — high abuse risk
	} else if sigStatus == "" && executable != "" {
		bonus += cfg.BonusUnknownSig // Unknown/missing status — telemetry gap, moderate concern
	}

	// Cap privilege bonus to prevent over-weighting
	// Industry standard: no single dimension should dominate >40% of the score range.
	if cfg.Cap > 0 && bonus > cfg.Cap {
		bonus = cfg.Cap
	}

	return bonus
}

// computeBurstBonus returns a bonus based on how many times the same rule
// category has fired in the last 5-minute window.
func computeBurstBonus(count int64, cfg BurstConfig) int {
	switch {
	case count >= cfg.ThresholdHigh:
		return cfg.BonusHigh
	case count >= cfg.ThresholdMed:
		return cfg.BonusMed
	case count >= cfg.ThresholdLow:
		return cfg.BonusLow
	default:
		return 0
	}
}

// computeFPDiscount returns points to subtract when the process carries
// strong trusted-binary signals (signed Microsoft binary from System32).
// The discount reduces alert priority for legitimate system activity.
//
// Industry alignment: Microsoft WDAC (Windows Defender Application Control)
// trust hierarchy — Microsoft-signed System32 binaries represent the highest
// trust level; third-party code-signed binaries are secondary.
func computeFPDiscount(sigStatus, executablePath string, cfg FalsePositiveConfig) int {
	sig := strings.ToLower(sigStatus)
	exe := strings.ToLower(executablePath)

	discount := 0

	// Microsoft-signed binary: trusted publisher
	if sig == "microsoft" {
		discount += cfg.DiscountMicrosoft

		// Additional discount for canonical system paths
		// These binaries are expected to run and are low-FP when not spawned suspiciously.
		systemPaths := []string{
			`\windows\system32\`,
			`\windows\syswow64\`,
			`\windows\sysnative\`,
		}
		for _, path := range systemPaths {
			if strings.Contains(exe, path) {
				discount += cfg.DiscountMicrosoftSystemPath
				break
			}
		}
	} else if sig == "trusted" {
		// Third-party vendor with a valid signing certificate
		discount += cfg.DiscountTrustedThirdParty
	}

	// Cap discount to prevent score from going very negative before clamp
	if cfg.DiscountCap > 0 && discount > cfg.DiscountCap {
		discount = cfg.DiscountCap
	}

	return discount
}

// computeFPRisk returns the false-positive probability (0.0–1.0) for the alert.
// This is stored separately from the discount for forensic transparency.
//
// FIX ISSUE-05: Recalibrated to industry-standard values.
// Reference: NIST SP 800-61r3 (Computer Security Incident Handling Guide)
// and empirical FP rates from enterprise EDR deployments (CrowdStrike 2024
// Falcon OverWatch report, Microsoft Defender for Endpoint benchmarks).
//
// The previous values were semantically inverted — Microsoft-signed binaries
// had fpRisk=0.35 (35% FP probability) but the suppression gate was set at
// 0.70, making FP risk effectively inert for all non-duplicate alerts.
//
// New calibration:
//   - Microsoft + System32: 0.70 → often suppressed (routine OS activity)
//   - Microsoft + other path: 0.45 → moderate FP likelihood
//   - Trusted (3rd party signed): 0.30 → lower FP, still plausible
//   - Unknown/missing signature: 0.15 → telemetry gap, somewhat suspicious
//   - Unsigned: 0.05 → very unlikely to be FP
func computeFPRisk(sigStatus, executablePath string, cfg FalsePositiveConfig) float64 {
	sig := strings.ToLower(sigStatus)
	exe := strings.ToLower(executablePath)

	isSystemPath := strings.Contains(exe, `\windows\system32\`) ||
		strings.Contains(exe, `\windows\syswow64\`)

	switch sig {
	case "microsoft":
		if isSystemPath {
			return cfg.RiskMicrosoftSystemPath
		}
		return cfg.RiskMicrosoftOtherPath
	case "trusted":
		return cfg.RiskTrustedThirdParty
	case "unsigned":
		return cfg.RiskUnsigned
	default:
		return cfg.RiskUnknownOrMissingSig
	}
}

// computeInteractionBonus calculates a non-linear cross-dimensional bonus
// when multiple high-severity contextual signals co-occur.
//
// Rationale (MITRE ATT&CK Kill Chain):
// A single signal (e.g., elevated privilege) is common in enterprise environments.
// But when lineage suspicion + privilege escalation + behavioral anomaly all
// co-occur, the probability of a true positive increases non-linearly.
// This models the combinatorial explosion of attack indicators.
//
// Calibration:
//   - 2 high signals co-occurring: +10 (notable convergence)
//   - 3+ high signals co-occurring: +15 (strong attack pattern)
//   - Cap: +15 (prevents runaway scores when combined with existing bonuses)
func computeInteractionBonus(lineageBonus, privilegeBonus, uebaBonus, burstBonus int, cfg InteractionConfig) int {
	// Count how many dimensions are contributing significant signal
	highSignals := 0
	if lineageBonus >= cfg.LineageHighThreshold {
		highSignals++ // Suspicious parent-child chain
	}
	if privilegeBonus >= cfg.PrivilegeHighThreshold {
		highSignals++ // Elevated/SYSTEM context
	}
	if uebaBonus > 0 {
		highSignals++ // Behavioral anomaly detected
	}
	if burstBonus >= cfg.BurstHighThreshold {
		highSignals++ // Rapid-fire temporal burst
	}

	switch {
	case highSignals >= 3:
		return minInt(cfg.BonusThreeSignals, cfg.Cap) // Strong multi-dimensional attack pattern
	case highSignals == 2:
		return minInt(cfg.BonusTwoSignals, cfg.Cap) // Notable signal convergence
	default:
		return 0
	}
}

// categoryKey derives a stable category identifier from a Sigma rule, used as
// the burst tracker's second key component.
// Priority: category from LogSource → product → rule ID prefix.
func categoryKey(rule *domain.SigmaRule) string {
	if rule == nil {
		return "unknown"
	}
	if rule.LogSource.Category != nil && *rule.LogSource.Category != "" {
		return strings.ToLower(*rule.LogSource.Category)
	}
	if rule.LogSource.Product != nil && *rule.LogSource.Product != "" {
		return strings.ToLower(*rule.LogSource.Product)
	}
	// Fall back to rule ID prefix (first 8 chars) for uniqueness
	if len(rule.ID) >= 8 {
		return rule.ID[:8]
	}
	return rule.ID
}

// clamp constrains an integer to [min, max].
func clamp(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// =============================================================================
// EventData Field Extractors (safe, no panics)
// =============================================================================

func extractString(data map[string]interface{}, key string) string {
	if v := resolveField(data, key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func extractInt64(data map[string]interface{}, key string) int64 {
	if v := resolveField(data, key); v != nil {
		switch n := v.(type) {
		case int64:
			return n
		case int:
			return int64(n)
		case float64:
			return int64(n)
		case uint32:
			return int64(n)
		case uint64:
			return int64(n)
		case uint:
			return int64(n)
		}
	}
	return 0
}

func extractBool(data map[string]interface{}, key string) bool {
	if v := resolveField(data, key); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
		if s, ok := v.(string); ok {
			return s == "1" || strings.EqualFold(s, "true")
		}
	}
	return false
}

func extractFloat64(data map[string]interface{}, key string) float64 {
	if v := resolveField(data, key); v != nil {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case int64:
			return float64(n)
		case uint:
			return float64(n)
		case uint64:
			return float64(n)
		}
	}
	return 0
}

func extractStringSlice(data map[string]interface{}, key string) []string {
	if v := resolveField(data, key); v != nil {
		switch arr := v.(type) {
		case []string:
			return arr
		case []interface{}:
			out := make([]string, 0, len(arr))
			for _, item := range arr {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

// computeContextQualityFactor converts context quality score [0..100] into a
// bounded multiplier [0.85..1.0]. This avoids overconfident scoring when key
// context fields are missing while still preserving signal continuity.
func computeContextQualityFactor(score float64, missingCount int, cfg QualityConfig) float64 {
	switch {
	case score >= 80:
		return cfg.ScoreGE80
	case score >= 60:
		return cfg.ScoreGE60
	case score >= 40:
		return cfg.ScoreGE40
	case score > 0:
		return cfg.ScoreGT0
	default:
		if missingCount == 0 {
			return cfg.ScoreGE80
		}
		return cfg.ScoreEQ0Missing
	}
}

func minInt(a, cap int) int {
	if cap <= 0 {
		return a
	}
	if a > cap {
		return cap
	}
	return a
}

// resolveField retrieves a value from a flat map[string]interface{} by checking
// the top-level key first, then falling back to the nested "data" sub-map.
//
// The Windows Agent serialises all process-specific fields inside a "data": {}
// JSON sub-object:
//
//	{ "event_type": "process", "data": { "pid": 1234, "name": "cmd.exe", ... } }
//
// The Kafka consumer flat-unmarshals the outer JSON, so these fields live at
// rawData["data"]["pid"], not rawData["pid"]. The field_mapper handles this
// transparently via sigmaToAgentData ("pid" → "data.pid"), but the risk scorer
// extractors were bypassing the mapper — always returning zero/empty for all
// process fields and causing GetLineageChain to fail at depth 0.
func resolveField(data map[string]interface{}, key string) interface{} {
	if data == nil {
		return nil
	}
	// 1. Top-level key (flat events, integration-test fixtures)
	if v, ok := data[key]; ok && v != nil {
		return v
	}
	// 2. Nested "data" sub-map (real Windows Agent events)
	if sub, ok := data["data"]; ok && sub != nil {
		if m, ok := sub.(map[string]interface{}); ok {
			if v, ok := m[key]; ok && v != nil {
				return v
			}
		}
	}
	return nil
}

// =============================================================================
// ContextSnapshot Builder
// =============================================================================

func buildContextSnapshot(
	input ScoringInput,
	chain []*infracache.ProcessLineageEntry,
	lineageSuspicion string,
	burstCount int64,
	burstWindowSec int,
	breakdown ScoreBreakdown,
) *ContextSnapshot {
	snap := &ContextSnapshot{
		ScoredAt:         time.Now().UTC(),
		LineageSuspicion: lineageSuspicion,
		BurstCount:       int(burstCount),
		BurstWindowSec:   burstWindowSec,
		ScoreBreakdown:   breakdown,
	}

	// Process image from event
	snap.ProcessName = extractString(input.Event.RawData, "name")
	snap.ProcessPath = extractString(input.Event.RawData, "executable")
	snap.ProcessCmdLine = extractString(input.Event.RawData, "command_line")

	// Privilege fields
	snap.UserSID = extractString(input.Event.RawData, "user_sid")
	snap.UserName = extractString(input.Event.RawData, "user_name")
	snap.IntegrityLevel = extractString(input.Event.RawData, "integrity_level")
	snap.IsElevated = extractBool(input.Event.RawData, "is_elevated")
	snap.SignatureStatus = extractString(input.Event.RawData, "signature_status")

	// Parent info from event fields (quick path)
	snap.ParentPID = extractInt64(input.Event.RawData, "ppid")
	snap.ParentName = extractString(input.Event.RawData, "parent_name")
	snap.ParentPath = extractString(input.Event.RawData, "parent_executable")

	// Populate richer lineage from cache chain
	if len(chain) > 0 {
		// chain[0] = target process; chain[1] = parent; chain[2] = grandparent
		if len(chain) >= 2 {
			snap.ParentName = chain[1].Name
			snap.ParentPath = chain[1].Executable
		}
		if len(chain) >= 3 {
			snap.GrandparentName = chain[2].Name
			snap.GrandparentPath = chain[2].Executable
		}

		// Serialise full chain for forensic replay
		snap.AncestorChain = make([]AncestorEntry, 0, len(chain))
		for _, e := range chain {
			snap.AncestorChain = append(snap.AncestorChain, AncestorEntry{
				PID:        e.PID,
				Name:       e.Name,
				Path:       e.Executable,
				UserSID:    e.UserSID,
				Integrity:  e.IntegrityLevel,
				IsElevated: e.IsElevated,
				SigStatus:  e.SignatureStatus,
				SeenAt:     e.SeenAt,
			})
		}
	}

	// Rule metadata
	primary := input.MatchResult.HighestSeverityMatch()
	if primary != nil && primary.Rule != nil {
		snap.RuleID = primary.Rule.ID
		snap.RuleTitle = primary.Rule.Title
		snap.RuleSeverity = primary.Rule.Severity().String()
		snap.RuleCategory = categoryKey(primary.Rule)
	}
	snap.MatchCount = input.MatchResult.MatchCount()
	snap.RelatedRules = input.MatchResult.RelatedRuleTitles()

	return snap
}

// dualUseBinaries are Windows binaries routinely abused for execution or
// proxying (LOLBAS). A valid Microsoft signature on them is no evidence of
// benign use, so they receive no signature-based false-positive discount.
var dualUseBinaries = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "powershell_ise.exe": true, "cmd.exe": true,
	"wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true,
	"regsvr32.exe": true, "msiexec.exe": true, "certutil.exe": true, "bitsadmin.exe": true,
	"wmic.exe": true, "msbuild.exe": true, "installutil.exe": true, "regasm.exe": true,
	"regsvcs.exe": true, "cmstp.exe": true, "msxsl.exe": true, "odbcconf.exe": true,
	"forfiles.exe": true, "pcalua.exe": true, "schtasks.exe": true, "sc.exe": true,
	"reg.exe": true, "net.exe": true, "net1.exe": true, "netsh.exe": true,
	"vssadmin.exe": true, "wevtutil.exe": true, "bcdedit.exe": true, "wbadmin.exe": true,
	"curl.exe": true, "ftp.exe": true, "hh.exe": true, "control.exe": true,
	"mavinject.exe": true, "msdt.exe": true, "esentutl.exe": true, "expand.exe": true,
	"extrac32.exe": true, "makecab.exe": true, "diskshadow.exe": true, "ntdsutil.exe": true,
	"procdump.exe": true, "psexec.exe": true, "at.exe": true, "atbroker.exe": true,
	"bash.exe": true, "wsl.exe": true, "dnscmd.exe": true, "findstr.exe": true,
}

func isDualUseBinary(executable string) bool {
	if executable == "" {
		return false
	}
	name := strings.ToLower(executable)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return dualUseBinaries[name]
}
