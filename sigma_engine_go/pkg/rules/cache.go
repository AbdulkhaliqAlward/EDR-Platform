package rules

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

// RuleCache stores parsed Sigma rules for fast startup.
// This is a performance optimization to avoid re-parsing thousands of YAML files on every run.
type RuleCache struct {
	Rules       []*domain.SigmaRule
	Timestamp   time.Time
	Version     string
	Fingerprint string
}

// cacheVersion must change whenever parsing semantics or the serialized rule
// shape change, so caches built by older engines are rejected and rules are
// re-parsed from disk. 2.0: list-of-maps selections (Selection.Alternatives),
// list conditions, strict keyword lists.
const cacheVersion = "2.0"

// SaveRulesToCache writes parsed rules to a cache file using gob encoding.
// The fingerprint should capture relevant config that changes which rules are loaded.
func SaveRulesToCache(rules []*domain.SigmaRule, cacheFile string, fingerprint string) error {
	if cacheFile == "" {
		return fmt.Errorf("cache file path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	tmp := cacheFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("failed to create cache file %s: %w", tmp, err)
	}
	defer func() {
		_ = f.Close()
	}()

	cache := &RuleCache{
		Rules:       rules,
		Timestamp:   time.Now(),
		Version:     cacheVersion,
		Fingerprint: fingerprint,
	}

	enc := gob.NewEncoder(f)
	if err := enc.Encode(cache); err != nil {
		return fmt.Errorf("failed to encode rule cache: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close cache file: %w", err)
	}

	// Atomic-ish replace on most platforms.
	if err := os.Rename(tmp, cacheFile); err != nil {
		return fmt.Errorf("failed to move cache into place: %w", err)
	}

	return nil
}

// LoadRulesFromCache loads cached rules if the cache file exists and is fresh enough.
// Returns an error on cache miss/expiry/mismatch.
func LoadRulesFromCache(cacheFile string, maxAge time.Duration, fingerprint string) ([]*domain.SigmaRule, error) {
	if cacheFile == "" {
		return nil, fmt.Errorf("cache file path is empty")
	}

	info, err := os.Stat(cacheFile)
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && time.Since(info.ModTime()) > maxAge {
		return nil, fmt.Errorf("cache expired")
	}

	f, err := os.Open(cacheFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cache RuleCache
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&cache); err != nil {
		return nil, fmt.Errorf("failed to decode cache: %w", err)
	}

	if cache.Version != cacheVersion {
		return nil, fmt.Errorf("cache version mismatch")
	}
	if fingerprint != "" && cache.Fingerprint != fingerprint {
		return nil, fmt.Errorf("cache fingerprint mismatch")
	}
	if len(cache.Rules) == 0 {
		return nil, fmt.Errorf("cache contains no rules")
	}

	// Re-compile regex patterns (gob doesn't serialize regexp.Regexp)
	// This is necessary because CompiledRegex field is not serialized
	for _, rule := range cache.Rules {
		recompileRegexPatterns(rule)
	}

	return cache.Rules, nil
}

// recompileRegexPatterns re-compiles regex patterns for all fields in a rule.
// This is called after loading from cache since regexp.Regexp cannot be serialized.
func recompileRegexPatterns(rule *domain.SigmaRule) {
	if rule == nil || rule.Detection.Selections == nil {
		return
	}

	for _, selection := range rule.Detection.Selections {
		if selection == nil {
			continue
		}

		for i := range selection.Fields {
			field := &selection.Fields[i]
			
			// Check if field has regex modifier
			hasRegexModifier := false
			for _, mod := range field.Modifiers {
				if strings.EqualFold(mod, "regex") || strings.EqualFold(mod, "re") {
					hasRegexModifier = true
					break
				}
			}

			if hasRegexModifier && len(field.Values) > 0 {
				// Re-compile regex patterns
				compiledRegex := make([]*regexp.Regexp, 0, len(field.Values))
				for _, val := range field.Values {
					patternStr := fmt.Sprintf("%v", val)
					re, err := regexp.Compile(patternStr)
					if err != nil {
						// Log warning but continue - invalid regex will fail at match time
						continue
					}
					compiledRegex = append(compiledRegex, re)
				}
				field.CompiledRegex = compiledRegex
			}
		}
	}
}


