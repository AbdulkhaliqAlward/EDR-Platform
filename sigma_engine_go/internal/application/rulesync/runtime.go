// Package rulesync keeps the running detector aligned with analyst rule edits.
package rulesync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"gopkg.in/yaml.v3"
)

type Runtime struct {
	source      database.RuleRepository
	engine      *detection.SigmaDetectionEngine
	quality     *rules.QualityFilter
	products    map[string]bool
	mu          sync.Mutex
	loaded      bool
	fingerprint [32]byte
}

func New(source database.RuleRepository, engine *detection.SigmaDetectionEngine, quality *rules.QualityFilter, products []string) *Runtime {
	r := &Runtime{source: source, engine: engine, quality: quality, products: make(map[string]bool)}
	for _, p := range products {
		r.products[strings.ToLower(p)] = true
	}
	return r
}

func Parse(row *database.Rule) (*domain.SigmaRule, error) {
	if row == nil {
		return nil, fmt.Errorf("missing rule")
	}
	rule, err := rules.NewRuleParser(true).ParseContent(row.Content)
	if err != nil {
		// Older seeding serialized the parsed domain form instead of Sigma YAML.
		var legacy domain.SigmaRule
		decoder := yaml.NewDecoder(strings.NewReader(row.Content))
		var extra interface{}
		if len(row.Content) > rules.DefaultMaxRuleSize || decoder.Decode(&legacy) != nil || decoder.Decode(&extra) != io.EOF || legacy.Validate() != nil {
			return nil, err
		}
		rule = &legacy
	}
	if rule.ID != "" && !strings.EqualFold(rule.ID, row.ID) {
		return nil, fmt.Errorf("content ID differs from the stored rule ID")
	}
	rule.ID = row.ID
	if row.Title != "" {
		rule.Title = row.Title
	}
	if row.Description != "" {
		rule.Description = row.Description
	}
	if row.Severity != "" {
		rule.Level = row.Severity
	}
	if row.Status != "" {
		rule.Status = row.Status
	}
	if row.Tags != nil {
		rule.Tags = append([]string(nil), row.Tags...)
	}
	if row.Product != "" {
		value := row.Product
		rule.LogSource.Product = &value
	}
	if row.Category != "" {
		value := row.Category
		rule.LogSource.Category = &value
	}
	if row.Service != "" {
		value := row.Service
		rule.LogSource.Service = &value
	}
	if err := detection.ValidateRule(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (r *Runtime) Validate(row *database.Rule) error {
	parsed, err := Parse(row)
	if err != nil {
		return err
	}
	// Persist complete metadata when clients submit only Sigma YAML.
	row.Title, row.Description, row.Severity = parsed.Title, parsed.Description, strings.ToLower(parsed.Level)
	row.Status = strings.ToLower(strings.TrimSpace(parsed.Status))
	if row.Status == "" {
		row.Status = "stable"
	}
	switch row.Status {
	case "stable", "test", "experimental", "deprecated":
	default:
		return fmt.Errorf("unsupported rule status %q", row.Status)
	}
	row.Tags = append([]string(nil), parsed.Tags...)
	row.MitreTechniques = append([]string(nil), parsed.MITRETechniques()...)
	row.MitreTactics = nil
	for _, tag := range parsed.Tags {
		low := strings.ToLower(tag)
		if strings.HasPrefix(low, "attack.") && !strings.HasPrefix(low, "attack.t") {
			row.MitreTactics = append(row.MitreTactics, strings.TrimPrefix(low, "attack."))
		}
	}
	if parsed.LogSource.Product != nil {
		row.Product = *parsed.LogSource.Product
	}
	if parsed.LogSource.Category != nil {
		row.Category = *parsed.LogSource.Category
	}
	if parsed.LogSource.Service != nil {
		row.Service = *parsed.LogSource.Service
	}
	return nil
}

// Refresh publishes a whole snapshot atomically. DB failures retain the
// previous snapshot; an unchanged fingerprint avoids recompilation.
func (r *Runtime) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows, err := r.source.LoadAll(ctx)
	if err != nil {
		return err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i] == nil {
			return rows[j] != nil
		}
		if rows[j] == nil {
			return false
		}
		return rows[i].ID < rows[j].ID
	})
	hash := sha256.New()
	for _, row := range rows {
		if row == nil {
			continue
		}
		data, _ := json.Marshal([]any{row.ID, row.Content, row.Enabled, row.Title, row.Description, row.Severity, row.Status, row.Tags, row.Product, row.Category, row.Service})
		hash.Write(data)
	}
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	if r.loaded && fingerprint == r.fingerprint {
		return nil
	}
	var active []*domain.SigmaRule
	for _, row := range rows {
		if row == nil || !row.Enabled {
			continue
		}
		rule, err := Parse(row)
		if err != nil {
			logger.Warnf("Stored rule %s rejected by runtime: %v", row.ID, err)
			continue
		}
		if !r.quality.Allows(rule) {
			continue
		}
		if len(r.products) > 0 && rule.LogSource.Product != nil && !r.products[strings.ToLower(*rule.LogSource.Product)] {
			continue
		}
		active = append(active, rule)
	}
	if err := r.engine.LoadRules(active); err != nil {
		return err
	}
	r.fingerprint, r.loaded = fingerprint, true
	return nil
}

func (r *Runtime) Start(ctx context.Context) {
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			refresh, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := r.Refresh(refresh)
			cancel()
			if err != nil && ctx.Err() == nil {
				logger.Warnf("Rule runtime refresh failed (previous snapshot retained): %v", err)
			}
		}
	}()
}

func (r *Runtime) Test(row *database.Rule, raw map[string]interface{}) ([]*domain.DetectionResult, error) {
	rule, err := Parse(row)
	if err != nil {
		return nil, err
	}
	event, err := domain.NewLogEvent(raw)
	if err != nil {
		return nil, err
	}
	return r.engine.TestRule(rule, event)
}
