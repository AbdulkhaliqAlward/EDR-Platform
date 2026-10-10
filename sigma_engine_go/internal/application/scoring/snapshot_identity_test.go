package scoring

import (
	"testing"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

func TestSnapshotDoesNotPresentFileAsProcess(t *testing.T) {
	for _, tc := range []struct {
		name, kind         string
		data               map[string]interface{}
		wantName, wantPath string
	}{
		{"missing actor", "file", map[string]interface{}{"name": "Microsoft.PowerShell.Commands.Utility", "process_name": "unknown", "process_path": "", "path": `C:\Modules\Microsoft.PowerShell.Commands.Utility`}, "", ""},
		{"measured actor", "file", map[string]interface{}{"name": "Utility.dll", "process_name": "powershell.exe", "process_path": `C:\Windows\powershell.exe`}, "powershell.exe", `C:\Windows\powershell.exe`},
		{"process legacy", "process", map[string]interface{}{"name": "cmd.exe"}, "cmd.exe", ""},
		{"registry target", "registry", map[string]interface{}{"name": "Run"}, "", ""},
		{"empty primary alias", "file", map[string]interface{}{"executable": "", "process_path": `C:\Windows\pwsh.exe`}, "pwsh.exe", `C:\Windows\pwsh.exe`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]interface{}{"event_type": tc.kind, "name": "misleading envelope", "data": tc.data}
			snap := buildContextSnapshot(ScoringInput{Event: &domain.LogEvent{RawData: raw}, MatchResult: &domain.EventMatchResult{}}, nil, "none", 0, 0, ScoreBreakdown{})
			if snap.ProcessName != tc.wantName || snap.ProcessPath != tc.wantPath {
				t.Fatalf("snapshot identity = %q, %q; want %q, %q", snap.ProcessName, snap.ProcessPath, tc.wantName, tc.wantPath)
			}
		})
	}
}
