package models

import (
	"encoding/json"
	"testing"
)

func TestPlaybookCommandAcceptsLegacyParams(t *testing.T) {
	var steps []PlaybookCommand
	raw := `[{"type":"quarantine_file","params":{"file_path":"{{alert.file_path}}"},"timeout":300},
	         {"type":"isolate_network","parameters":{"x":"y"},"timeout":60,"on_failure":"stop"},
	         {"type":"run_script","script_id":"abc","timeout":120}]`
	if err := json.Unmarshal([]byte(raw), &steps); err != nil {
		t.Fatal(err)
	}
	if got := steps[0].Parameters["file_path"]; got != "{{alert.file_path}}" {
		t.Fatalf("legacy params not loaded: %v", got)
	}
	if steps[1].Parameters["x"] != "y" || steps[1].OnFailure != "stop" {
		t.Fatalf("parameters not loaded: %+v", steps[1])
	}
	if steps[2].ScriptID != "abc" {
		t.Fatalf("script_id not loaded: %+v", steps[2])
	}
}
