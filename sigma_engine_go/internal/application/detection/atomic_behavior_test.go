package detection

import (
	"path/filepath"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/stretchr/testify/require"
)

// Behavioral fixtures derived from the pinned Atomic definitions referenced in
// each rule. These are inert event strings, never executable test invocations.
// Passing proves matching and routing, not that an endpoint emits the evidence.
func TestAtomicBehaviorFixtures(t *testing.T) {
	tests := []struct {
		guid, file, positive, negative, image string
	}{
		{"88f6327e-51ec-4bbf-b2e8-3fea534eab8b", "mitras_ps_raw_volume_read.yml", `New-Object IO.FileStream "\\.\C:", 'Open', 'Read', 'ReadWrite'`, `New-Object IO.FileStream "C:\backup.txt", 'Open', 'Read', 'ReadWrite'`, ""},
		{"faab755e-4299-48ec-8202-fc7885eb6545", "mitras_ps_browser_discovery.yml", `Get-ChildItem -Path C:\Users\ -Filter Bookmarks -Recurse -Force`, `Get-ChildItem -Path C:\Users\ -Filter Documents -Recurse -Force`, ""},
		{"74094120-e1f5-47c9-b162-a418a0f624d5", "mitras_ps_browser_discovery.yml", `Get-Content -Path "C:\Users\analyst\AppData\Local\Microsoft\Edge\User Data\Default\History" | Select-String https`, `Get-Content -Path "C:\logs\History.txt"`, ""},
		{"cfe6315c-4945-40f7-b5a4-48f7af2262af", "mitras_ps_browser_discovery.yml", `Get-Content -Path "C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\History"`, `Get-Item "C:\Users\analyst\AppData\Local\Google\Chrome\User Data\Default\History"`, ""},
		{"76f71e2f-480e-4bed-b61e-398fe17499d5", "mitras_proc_browser_discovery.yml", `where /R C:\Users\ Bookmarks`, `where /R C:\Users\ Documents`, `C:\Windows\System32\where.exe`},
		{"4312cdbc-79fc-4a9c-becc-53d49c734bc5", "mitras_proc_browser_discovery.yml", `where /R C:\Users\ places.sqlite`, `where places.sqlite`, `C:\Windows\System32\where.exe`},
		{"727dbcdb-e495-4ab1-a6c4-80c7f77aef85", "mitras_proc_browser_discovery.yml", `cmd /c dir /s /b C:\Users\analyst\Favorites`, `cmd /c dir /s /b C:\Users\analyst\Documents`, `C:\Windows\System32\cmd.exe`},
		{"7a8f8ae9-6b1d-4f7b-88e7-9ea01234eee5", "mitras_ps_pipe_integrity_reduction.yml", `NamedPipeServerStream SetSecurityInfo S:(ML;;NW;;;S-1-16-0)`, `NamedPipeServerStream SetSecurityInfo S:(ML;;NW;;;S-1-16-8192)`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.guid, func(t *testing.T) {
			r, err := rules.NewRuleParser(false).ParseFile(filepath.Join("../../../sigma_rules/rules/edr_custom", tc.file))
			require.NoError(t, err)
			require.NoError(t, ValidateRule(r))
			engine := newTestEngine(t, r)
			makeEvent := func(text string, wrongSource bool) *domain.LogEvent {
				typeName := "powershell"
				data := map[string]interface{}{"event_id": 4104, "script_block_text": text}
				if tc.image != "" {
					typeName = "process"
					data = map[string]interface{}{"executable": tc.image, "command_line": text}
				}
				if wrongSource {
					typeName = "dns"
					data = map[string]interface{}{"query_name": text}
				}
				return agentEvent(t, typeName, data)
			}
			require.NotEmpty(t, engine.Detect(makeEvent(tc.positive, false)), "positive evidence must match")
			require.True(t, engine.DetectAggregated(makeEvent(tc.positive, false)).HasMatches(), "Kafka aggregate detection must agree")
			require.Empty(t, engine.Detect(makeEvent(tc.negative, false)), "nearby legitimate behavior must not match this rule")
			require.Empty(t, engine.Detect(makeEvent(tc.positive, true)), "unrelated telemetry must not masquerade as script/process evidence")
		})
	}
}
