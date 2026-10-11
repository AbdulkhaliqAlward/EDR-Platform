package detection

import (
	"path/filepath"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/stretchr/testify/require"
)

// The agent's event-log collector forwards Security / System / Defender
// records as event_type "eventlog" with the channel, provider, EventID and the
// record's EventData fields under their original Windows names. Those events
// must reach service-scoped SigmaHQ rules (no category) and resolve fields such
// as SamAccountName, ImagePath and Provider_Name exactly as in the XML.
func TestEventLogServiceRules(t *testing.T) {
	base := "../../../sigma_rules/rules/windows/builtin"
	tests := []struct {
		file     string
		positive map[string]interface{}
		negative map[string]interface{}
	}{
		{"system/service_control_manager/win_system_powershell_script_installed_as_service.yml",
			map[string]interface{}{"channel": "System", "provider_name": "Service Control Manager", "EventID": 7045, "ServiceName": "updater", "ImagePath": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File C:\x.ps1`},
			map[string]interface{}{"channel": "System", "provider_name": "Service Control Manager", "EventID": 7045, "ServiceName": "spooler", "ImagePath": `C:\Windows\System32\spoolsv.exe`}},
		{"security/win_security_new_or_renamed_user_account_with_dollar_sign.yml",
			map[string]interface{}{"channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing", "EventID": 4720, "SamAccountName": "svc$", "TargetUserName": "svc$"},
			map[string]interface{}{"channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing", "EventID": 4720, "SamAccountName": "alice", "TargetUserName": "alice"}},
		{"windefend/win_defender_real_time_protection_disabled.yml",
			map[string]interface{}{"channel": "Microsoft-Windows-Windows Defender/Operational", "provider_name": "Microsoft-Windows-Windows Defender", "EventID": 5001},
			map[string]interface{}{"channel": "Microsoft-Windows-Windows Defender/Operational", "provider_name": "Microsoft-Windows-Windows Defender", "EventID": 5000}},
	}
	for _, tc := range tests {
		t.Run(filepath.Base(tc.file), func(t *testing.T) {
			r, err := rules.NewRuleParser(false).ParseFile(filepath.Join(base, tc.file))
			require.NoError(t, err)
			require.NoError(t, ValidateRule(r))
			engine := newTestEngine(t, r)
			ev := func(data map[string]interface{}) *domain.LogEvent {
				d := map[string]interface{}{"action": "eventlog", "event_code": data["EventID"]}
				for k, v := range data {
					d[k] = v
				}
				return agentEvent(t, "eventlog", d)
			}
			require.True(t, engine.DetectAggregated(ev(tc.positive)).HasMatches(), "matching record must alert")
			require.False(t, engine.DetectAggregated(ev(tc.negative)).HasMatches(), "non-matching record must not alert")
			// The same fields on another channel must not reach a service-scoped rule.
			wrong := map[string]interface{}{}
			for k, v := range tc.positive {
				wrong[k] = v
			}
			wrong["channel"] = "Application"
			require.False(t, engine.DetectAggregated(ev(wrong)).HasMatches(), "rules are scoped to their channel's service")
		})
	}
}
