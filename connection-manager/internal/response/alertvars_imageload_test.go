package response

import (
	"testing"

	"github.com/edr-platform/connection-manager/internal/repository"
)

// Image-load alerts: the actor is the loading process (pid, image, start time
// for identity checks); the artifact to scan/quarantine is the loaded module,
// consistent with the module's hash.
func TestBuildAlertVarsImageLoad(t *testing.T) {
	a := &repository.SigmaAlertRecord{ID: "a1", AgentID: "ag", Category: "image_load", ContextData: map[string]any{
		"event_type": "image_load",
		"data": map[string]any{
			"pid": 34144, "executable": `C:\Tools\loader.exe`, "process_name": "loader.exe",
			"process_start_time": "2026-10-12T00:19:40.123Z", "command_line": `"C:\Tools\loader.exe" -x`,
			"parent_executable": `C:\Windows\explorer.exe`, "user_name": `WS\alice`,
			"ImageLoaded": `C:\Tools\dbghelp.dll`, "path": `C:\Tools\dbghelp.dll`, "hash_sha256": "ab12",
		},
	}}
	v := BuildAlertVars(a)
	want := map[string]string{
		"pid": "34144", "process_path": `C:\Tools\loader.exe`, "process_name": "loader.exe",
		"process_started_at": "2026-10-12T00:19:40.123Z", "parent_process_path": `C:\Windows\explorer.exe`,
		"user": `WS\alice`, "file_path": `C:\Tools\dbghelp.dll`, "sha256": "ab12",
	}
	for k, w := range want {
		if v[k] != w {
			t.Fatalf("%s = %q, want %q", k, v[k], w)
		}
	}
}

func TestBuildAlertVarsIgnoresPlaceholderNames(t *testing.T) {
	a := &repository.SigmaAlertRecord{ID: "a2", ContextData: map[string]any{
		"event_type": "network",
		"data":       map[string]any{"pid": 7, "process_name": "pid:7", "Image": `C:\x\evil.exe`},
	}, MatchedFields: map[string]any{"Image": `C:\x\evil.exe`}}
	v := BuildAlertVars(a)
	if v["process_name"] != "evil.exe" {
		t.Fatalf("placeholder used as process name: %q", v["process_name"])
	}
	old := &repository.SigmaAlertRecord{ID: "a3", ContextData: map[string]any{
		"event_type": "image_load", "data": map[string]any{"pid": 9, "process_name": "unknown"},
	}}
	if v := BuildAlertVars(old); v["process_name"] != "" {
		t.Fatalf("placeholder used as process name: %q", v["process_name"])
	}
}
