package detection

import (
	"path/filepath"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/stretchr/testify/require"
)

// Real shipped Sigma rules, synthetic evidence only: no attack command is run.
func TestShippedRulesReceiveSysmonStreamAndRawDiskEvents(t *testing.T) {
	tests := []struct {
		path, category, image string
		code                  int
	}{
		{"create_stream_hash/create_stream_hash_regedit_export_to_ads.yml", "create_stream_hash", `C:\Windows\regedit.exe`, 15},
		{"raw_access_thread/raw_access_thread_susp_disk_access_using_uncommon_tools.yml", "raw_access_thread", `C:\Users\user\Downloads\unknown.exe`, 9},
	}
	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			rule, err := rules.NewRuleParser(false).ParseFile(filepath.Join("../../../sigma_rules/rules/windows", tc.path))
			require.NoError(t, err)
			engine := newTestEngine(t, rule)
			event, err := domain.NewLogEvent(map[string]interface{}{"EventID": tc.code, "Image": tc.image, "Device": `\Device\HarddiskVolume1`, "TargetFilename": `C:\Users\user\Downloads\file.txt:payload`})
			require.NoError(t, err)
			require.Equal(t, tc.category, string(event.Category))
			require.NotEmpty(t, engine.Detect(event), "shipped rule must receive and match its event source")
			negative, err := domain.NewLogEvent(map[string]interface{}{"EventID": 1, "Image": tc.image})
			require.NoError(t, err)
			require.Empty(t, engine.Detect(negative), "process creation must not impersonate stream/disk events")
		})
	}
}

func TestLegacyGlobalAllowlistCannotHideMatchedBehavior(t *testing.T) {
	r := rule(t, "trusted-image-abuse", "process_creation", "detection:\n  selection:\n    CommandLine|contains: 'suspicious-behavior-marker'\n  condition: selection\n")
	engine := newTestEngine(t, r)
	engine.quality.Filtering = FilteringConfig{Enabled: true, WhitelistedProcesses: []string{`C:\Windows\System32\svchost.exe`, `*\Code.exe`}}
	for _, image := range []string{`C:\Windows\System32\svchost.exe`, `C:\Users\user\Code.exe`} {
		event := agentEvent(t, "process", map[string]interface{}{"executable": image, "command_line": "suspicious-behavior-marker"})
		require.NotEmpty(t, engine.Detect(event), "trusted image paths cannot prove benign behavior")
		require.True(t, engine.DetectAggregated(event).HasMatches(), "Kafka aggregation must not bypass the rule either")
	}
}
