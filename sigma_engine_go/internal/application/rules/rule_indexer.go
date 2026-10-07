package rules

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

// RuleIndexer provides O(1) rule lookup by logsource with statistics.
type RuleIndexer struct {
	// Exact matches: "product:category:service" -> rules
	index map[string][]*domain.SigmaRule

	// Partial matches for wildcards
	categoryIndex map[string][]*domain.SigmaRule // "product:category" -> rules
	productIndex  map[string][]*domain.SigmaRule  // "product" -> rules

	// serviceIndex holds rules that select by service only (no category):
	// "product:service" -> rules.
	serviceIndex map[string][]*domain.SigmaRule

	// candidateCache memoises GetCandidateRules results per
	// (product, categories, service) key; reset whenever the index changes.
	// Guarded by cacheMu so lookups only need mu.RLock.
	candidateCache map[string][]*domain.SigmaRule
	cacheMu        sync.Mutex

	// All rules (fallback)
	allRules []*domain.SigmaRule

	// Statistics
	stats IndexStats

	mu sync.RWMutex
}

// IndexStats tracks indexing and lookup statistics.
type IndexStats struct {
	TotalRules      int
	RulesPerProduct map[string]int
	RulesPerCategory map[string]int
	IndexBuildTime  time.Duration
	LookupCount     int64
	LookupTimeTotal time.Duration
}

// NewRuleIndexer creates a new rule indexer.
func NewRuleIndexer() *RuleIndexer {
	return &RuleIndexer{
		index:         make(map[string][]*domain.SigmaRule),
		categoryIndex: make(map[string][]*domain.SigmaRule),
		productIndex:  make(map[string][]*domain.SigmaRule),
		serviceIndex:  make(map[string][]*domain.SigmaRule),
		allRules:      make([]*domain.SigmaRule, 0),
		candidateCache: make(map[string][]*domain.SigmaRule),
		stats: IndexStats{
			RulesPerProduct:  make(map[string]int),
			RulesPerCategory: make(map[string]int),
		},
	}
}

// BuildIndex builds the index from a list of rules.
func (ri *RuleIndexer) BuildIndex(rules []*domain.SigmaRule) {
	start := time.Now()

	ri.mu.Lock()
	defer ri.mu.Unlock()

	// Clear existing index
	ri.index = make(map[string][]*domain.SigmaRule)
	ri.categoryIndex = make(map[string][]*domain.SigmaRule)
	ri.productIndex = make(map[string][]*domain.SigmaRule)
	ri.serviceIndex = make(map[string][]*domain.SigmaRule)
	ri.allRules = rules
	ri.resetCandidateCache()

	// Build indexes
	for _, rule := range rules {
		ri.indexRule(rule)
	}

	// Update statistics
	ri.stats.TotalRules = len(rules)
	ri.stats.IndexBuildTime = time.Since(start)

	// Count rules per product
	for product, rules := range ri.productIndex {
		ri.stats.RulesPerProduct[product] = len(rules)
	}

	// Count rules per category
	for category, rules := range ri.categoryIndex {
		ri.stats.RulesPerCategory[category] = len(rules)
	}
}

// GetRules returns rules matching the given logsource parameters.
// Uses O(1) lookup with fallback to partial matches.
//
// S9 FIX: Returns the internal slice directly (no defensive copy).
// Rules are immutable after LoadRules() and are protected by the RLock.
// Callers must NOT mutate the returned slice.
func (ri *RuleIndexer) GetRules(product, category, service string) []*domain.SigmaRule {
	start := time.Now()

	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Try exact match first
	key := fmt.Sprintf("%s:%s:%s", product, category, service)
	if rules, ok := ri.index[key]; ok {
		ri.updateLookupStats(time.Since(start))
		return rules
	}

	// Try category match (product:category:*)
	catKey := fmt.Sprintf("%s:%s", product, category)
	if rules, ok := ri.categoryIndex[catKey]; ok {
		ri.updateLookupStats(time.Since(start))
		return rules
	}

	// Try product match (product:*:*)
	if rules, ok := ri.productIndex[product]; ok {
		ri.updateLookupStats(time.Since(start))
		return rules
	}

	// Fallback to all rules
	ri.updateLookupStats(time.Since(start))
	return ri.allRules
}

// GetRulesStrict returns only rules that match the event logsource category.
// Unlike GetRules, it does NOT fall back to product-wide or all-rules sets.
// This prevents cross-category evaluation (e.g. image_load events tested against
// process_creation/file rules) which can distort matching and confidence.
func (ri *RuleIndexer) GetRulesStrict(product, category, service string) []*domain.SigmaRule {
	start := time.Now()

	ri.mu.RLock()
	defer ri.mu.RUnlock()

	// Try exact match first
	key := fmt.Sprintf("%s:%s:%s", product, category, service)
	if rules, ok := ri.index[key]; ok {
		ri.updateLookupStats(time.Since(start))
		return rules
	}

	// Try category match (product:category:*)
	catKey := fmt.Sprintf("%s:%s", product, category)
	if rules, ok := ri.categoryIndex[catKey]; ok {
		ri.updateLookupStats(time.Since(start))
		return rules
	}

	ri.updateLookupStats(time.Since(start))
	return []*domain.SigmaRule{}
}

// GetRulesByCategory returns all rules for a specific category.
func (ri *RuleIndexer) GetRulesByCategory(category string) []*domain.SigmaRule {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	var result []*domain.SigmaRule
	for key, rules := range ri.categoryIndex {
		if strings.Contains(key, ":"+category) {
			result = append(result, rules...)
		}
	}

	return copyRules(result)
}

// GetRulesByProduct returns all rules for a specific product.
func (ri *RuleIndexer) GetRulesByProduct(product string) []*domain.SigmaRule {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	if rules, ok := ri.productIndex[product]; ok {
		return copyRules(rules)
	}
	return []*domain.SigmaRule{}
}

// GetAllRules returns all indexed rules.
func (ri *RuleIndexer) GetAllRules() []*domain.SigmaRule {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return copyRules(ri.allRules)
}

// AddRule adds a single rule to the index.
func (ri *RuleIndexer) AddRule(rule *domain.SigmaRule) error {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	// Check for duplicate ID
	for _, existing := range ri.allRules {
		if existing.ID == rule.ID {
			return fmt.Errorf("rule already exists: %s", rule.ID)
		}
	}

	// Add to all rules
	ri.allRules = append(ri.allRules, rule)
	ri.stats.TotalRules++
	ri.indexRule(rule)
	if rule.LogSource.Product != nil {
		ri.stats.RulesPerProduct[*rule.LogSource.Product]++
	}
	ri.resetCandidateCache()

	return nil
}

// RemoveRule removes a rule from the index.
func (ri *RuleIndexer) RemoveRule(ruleID string) error {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	// Find rule
	var rule *domain.SigmaRule
	idx := -1
	for i, r := range ri.allRules {
		if r.ID == ruleID {
			rule = r
			idx = i
			break
		}
	}

	if idx < 0 {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	// Remove from all rules. Copy-on-write: never mutate a slice a
	// concurrent reader may hold.
	remaining := make([]*domain.SigmaRule, 0, len(ri.allRules)-1)
	remaining = append(remaining, ri.allRules[:idx]...)
	remaining = append(remaining, ri.allRules[idx+1:]...)
	ri.allRules = remaining
	ri.stats.TotalRules--

	// Remove from indexes
	removeFrom(ri.index, ri.buildKey(rule.LogSource), ruleID)
	if rule.LogSource.Product != nil && rule.LogSource.Category != nil {
		removeFrom(ri.categoryIndex, fmt.Sprintf("%s:%s", *rule.LogSource.Product, *rule.LogSource.Category), ruleID)
	}
	if rule.LogSource.Product != nil && rule.LogSource.Category == nil && rule.LogSource.Service != nil {
		removeFrom(ri.serviceIndex, fmt.Sprintf("%s:%s", *rule.LogSource.Product, *rule.LogSource.Service), ruleID)
	}
	if rule.LogSource.Product != nil {
		product := *rule.LogSource.Product
		removeFrom(ri.productIndex, product, ruleID)
		ri.stats.RulesPerProduct[product]--
	}
	ri.resetCandidateCache()

	return nil
}

// removeFrom removes ruleID from idx[key] without mutating the existing
// backing array (readers may hold it) and deletes the key when empty.
// The previous implementation re-sliced a local copy, so the map entry kept
// its old length and the last rule appeared twice after a removal.
func removeFrom(idx map[string][]*domain.SigmaRule, key, ruleID string) {
	cur := idx[key]
	next := make([]*domain.SigmaRule, 0, len(cur))
	for _, r := range cur {
		if r.ID != ruleID {
			next = append(next, r)
		}
	}
	if len(next) == 0 {
		delete(idx, key)
		return
	}
	idx[key] = next
}

// indexRule adds a rule to every index it belongs to. Caller holds ri.mu.
func (ri *RuleIndexer) indexRule(rule *domain.SigmaRule) {
	key := ri.buildKey(rule.LogSource)
	ri.index[key] = append(ri.index[key], rule)

	if rule.LogSource.Product != nil && rule.LogSource.Category != nil {
		catKey := fmt.Sprintf("%s:%s", *rule.LogSource.Product, *rule.LogSource.Category)
		ri.categoryIndex[catKey] = append(ri.categoryIndex[catKey], rule)
	}
	if rule.LogSource.Product != nil && rule.LogSource.Category == nil && rule.LogSource.Service != nil {
		svcKey := fmt.Sprintf("%s:%s", *rule.LogSource.Product, *rule.LogSource.Service)
		ri.serviceIndex[svcKey] = append(ri.serviceIndex[svcKey], rule)
	}
	if rule.LogSource.Product != nil {
		product := *rule.LogSource.Product
		ri.productIndex[product] = append(ri.productIndex[product], rule)
	}
}

func (ri *RuleIndexer) resetCandidateCache() {
	ri.cacheMu.Lock()
	ri.candidateCache = make(map[string][]*domain.SigmaRule)
	ri.cacheMu.Unlock()
}

// GetCandidateRules returns every rule whose logsource is compatible with an
// event of the given product, categories (primary first, then generic
// parents such as registry_event) and service:
//   - category rules for each of the event's categories; a rule that also
//     names a service only applies when the event has that service;
//   - service-only rules (no category) for the event's service.
//
// The union is de-duplicated and memoised per (product, categories, service).
// Callers must not mutate the returned slice.
func (ri *RuleIndexer) GetCandidateRules(product string, categories []string, service string) []*domain.SigmaRule {
	key := product + "|" + strings.Join(categories, ",") + "|" + service

	ri.mu.RLock()
	defer ri.mu.RUnlock()

	ri.cacheMu.Lock()
	cached, ok := ri.candidateCache[key]
	ri.cacheMu.Unlock()
	if ok {
		return cached
	}

	seen := make(map[*domain.SigmaRule]struct{})
	out := make([]*domain.SigmaRule, 0, 64)
	add := func(rules []*domain.SigmaRule, requireService bool) {
		for _, r := range rules {
			if _, dup := seen[r]; dup {
				continue
			}
			if requireService && r.LogSource.Service != nil && !strings.EqualFold(*r.LogSource.Service, service) {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	for _, c := range categories {
		if c == "" || c == string(domain.EventCategoryUnknown) {
			continue
		}
		add(ri.categoryIndex[product+":"+c], true)
	}
	if service != "" {
		add(ri.serviceIndex[product+":"+service], false)
	}

	ri.cacheMu.Lock()
	ri.candidateCache[key] = out
	ri.cacheMu.Unlock()
	return out
}

// buildKey builds an index key from a logsource.
func (ri *RuleIndexer) buildKey(ls domain.LogSource) string {
	product := "*"
	if ls.Product != nil {
		product = *ls.Product
	}
	category := "*"
	if ls.Category != nil {
		category = *ls.Category
	}
	service := "*"
	if ls.Service != nil {
		service = *ls.Service
	}
	return fmt.Sprintf("%s:%s:%s", product, category, service)
}

// updateLookupStats updates lookup statistics (thread-safe).
func (ri *RuleIndexer) updateLookupStats(duration time.Duration) {
	// Use atomic operations for counters
	// Note: This is approximate, exact stats would require more synchronization
	ri.stats.LookupCount++
	ri.stats.LookupTimeTotal += duration
}

// Stats returns indexing statistics.
func (ri *RuleIndexer) Stats() IndexStats {
	ri.mu.RLock()
	defer ri.mu.RUnlock()

	stats := ri.stats
	stats.RulesPerProduct = make(map[string]int)
	stats.RulesPerCategory = make(map[string]int)

	for k, v := range ri.stats.RulesPerProduct {
		stats.RulesPerProduct[k] = v
	}
	for k, v := range ri.stats.RulesPerCategory {
		stats.RulesPerCategory[k] = v
	}

	return stats
}

// copyRules creates a copy of the rules slice to prevent external modification.
func copyRules(rules []*domain.SigmaRule) []*domain.SigmaRule {
	if rules == nil {
		return nil
	}
	result := make([]*domain.SigmaRule, len(rules))
	copy(result, rules)
	return result
}

