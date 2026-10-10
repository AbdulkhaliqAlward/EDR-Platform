package detection

import (
	"path/filepath"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/stretchr/testify/require"
)

func TestAtomicT1087001LocalDiscovery(t *testing.T) {
	tests := []struct {
		file, kind           string
		positives, negatives []string
	}{
		{"mitras_proc_local_account_discovery.yml", "process", []string{`net user`, `net localgroup`, `net localgroup "Users"`, `"C:\Windows\System32\net.exe" user`, `net1.exe user administrator`, `NET.EXE LOCALGROUP Users`}, []string{`net user attacker password /add`, `net user administrator /delete`, `net localgroup Users attacker /add`, `net user /domain`, `net use \\server\share`, `net start`, `net user & whoami`}},
		{"mitras_ps_local_account_discovery.yml", "powershell", []string{`get-localuser`, `Get-LocalGroupMember -Group Users`, `Get-LocalGroup`, `Microsoft.PowerShell.LocalAccounts\Get-LocalUser`}, []string{`Get-LocalUserBackup`, `New-LocalUser user`, `Get-Date`}},
		{"mitras_pm_local_account_discovery.yml", "module", []string{`CommandInvocation(Get-LocalUser): "Get-LocalUser"`, `CommandInvocation(Get-LocalGroupMember): "Get-LocalGroupMember"`}, []string{`CommandInvocation(New-LocalUser)`, `ParameterBinding(Write-Output): name="InputObject"; value="Get-LocalUser"`}},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			r, err := rules.NewRuleParser(false).ParseFile(filepath.Join("../../../sigma_rules/rules/edr_custom", tc.file))
			require.NoError(t, err)
			engine := newTestEngine(t, r)
			for _, positive := range []bool{true, false} {
				values := tc.negatives
				if positive {
					values = tc.positives
				}
				for _, value := range values {
					kind := "powershell"
					data := map[string]interface{}{"event_code": 4104, "script_block_text": value}
					if tc.kind == "module" {
						data = map[string]interface{}{"event_code": 4103, "action": "module", "payload": value}
					}
					if tc.kind == "process" {
						kind = "process"
						data = map[string]interface{}{"executable": `C:\Windows\System32\net.exe`, "command_line": value}
					}
					ev := agentEvent(t, kind, data)
					matches := engine.Detect(ev)
					require.Equal(t, positive, len(matches) > 0, "%s", value)
					require.Equal(t, positive, engine.DetectAggregated(ev).HasMatches(), "aggregate %s", value)
				}
			}
		})
	}
}
