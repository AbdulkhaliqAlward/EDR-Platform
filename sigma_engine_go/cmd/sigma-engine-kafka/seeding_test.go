package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/application/rulesync"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/config"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestShippedRulesSurviveNewAndLegacyDatabaseContent(t *testing.T) {
	logger.SetLevel("error")
	cfg, err := config.LoadConfig("../../config/config.yaml")
	require.NoError(t, err)
	cfg.Rules.RulesDirectory = filepath.Join("../..", cfg.Rules.RulesDirectory)
	cfg.Rules.CacheFile = "" // never use or change application caches in tests
	cfg.Rules.ParallelWorkers = 4
	index, err := loadRules(context.Background(), cfg)
	require.NoError(t, err)
	require.NotEmpty(t, index.Rules)
	for _, original := range index.Rules {
		for _, selection := range original.Detection.Selections {
			sortSelectionFields(selection)
		}
		require.NoError(t, detection.ValidateRule(original), original.ID)
		row := domainRuleToDBRule(original)
		require.NotNil(t, row, original.ID)
		// New content must be portable Sigma, independent of the legacy adapter.
		canonical, err := rules.NewRuleParser(true).ParseContent(row.Content)
		require.NoError(t, err, original.ID)
		require.NoError(t, detection.ValidateRule(canonical), original.ID)
		legacy, err := yaml.Marshal(original)
		require.NoError(t, err)
		want, err := json.Marshal(original.Detection)
		require.NoError(t, err)
		for _, variant := range []string{row.Content, string(legacy)} {
			parsed, err := rulesync.Parse(&database.Rule{ID: row.ID, Content: variant})
			require.NoError(t, err, original.ID)
			for _, selection := range parsed.Detection.Selections {
				sortSelectionFields(selection)
			}
			got, err := json.Marshal(parsed.Detection)
			require.NoError(t, err)
			require.JSONEq(t, string(want), string(got), original.ID)
		}
	}
	t.Logf("Verified %d shipped eligible rules through canonical and legacy stored content", len(index.Rules))
}

// Sigma field maps are AND groups; Go map iteration order is immaterial.
func sortSelectionFields(s *domain.Selection) {
	sort.Slice(s.Fields, func(i, j int) bool {
		return s.Fields[i].FieldName+"|"+strings.Join(s.Fields[i].Modifiers, "|") < s.Fields[j].FieldName+"|"+strings.Join(s.Fields[j].Modifiers, "|")
	})
	for i := range s.Alternatives {
		sortSelectionFields(&s.Alternatives[i])
	}
}
