package detection

import (
	"testing"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

func mustEvent(t *testing.T, raw map[string]interface{}) *domain.LogEvent {
	t.Helper()
	e, err := domain.NewLogEvent(raw)
	if err != nil {
		t.Fatalf("NewLogEvent failed: %v", err)
	}
	return e
}

func TestIsAgentSelfEvent_ParentExecutableFullPath(t *testing.T) {
	e := mustEvent(t, map[string]interface{}{
		"event_type": "process",
		"data": map[string]interface{}{
			"name":              "powershell.exe",
			"parent_executable": `C:\ProgramData\EDR\bin\edr-agent.exe`,
			"parent_name":       "edr-agent.exe",
		},
	})
	if !isAgentSelfEvent(e) {
		t.Fatal("expected event with agent parent_executable to be flagged as self")
	}
}

func TestIsAgentSelfEvent_ParentNameOnlyIsNotTrusted(t *testing.T) {
	// A name alone is attacker-controllable: never suppress on it.
	e := mustEvent(t, map[string]interface{}{
		"event_type": "process",
		"data": map[string]interface{}{
			"name":        "powershell.exe",
			"parent_name": "edr-agent.exe",
		},
	})
	if isAgentSelfEvent(e) {
		t.Fatal("parent name alone must not mark an event as agent activity")
	}
}

func TestIsAgentSelfEvent_LookalikePathIsNotTrusted(t *testing.T) {
	e := mustEvent(t, map[string]interface{}{
		"event_type": "process",
		"data": map[string]interface{}{
			"name":              "powershell.exe",
			"parent_executable": "C:" + string(rune(92)) + "Users" + string(rune(92)) + "bob" + string(rune(92)) + "edr-agent.exe",
		},
	})
	if isAgentSelfEvent(e) {
		t.Fatal("a look-alike agent binary outside the install directory must not be trusted")
	}
}

func TestIsAgentSelfEvent_SigmaParentImage(t *testing.T) {
	e := mustEvent(t, map[string]interface{}{
		"event_type":  "process",
		"ParentImage": `C:\Program Files\EDR\edr-agent.exe`,
	})
	if !isAgentSelfEvent(e) {
		t.Fatal("expected event with Sigma ParentImage pointing at agent to be flagged as self")
	}
}

func TestIsAgentSelfEvent_BenignParent(t *testing.T) {
	e := mustEvent(t, map[string]interface{}{
		"event_type": "process",
		"data": map[string]interface{}{
			"name":              "powershell.exe",
			"parent_executable": `C:\Windows\explorer.exe`,
			"parent_name":       "explorer.exe",
		},
	})
	if isAgentSelfEvent(e) {
		t.Fatal("benign parent must NOT be flagged as self")
	}
}

func TestIsAgentSelfEvent_NoParentFields(t *testing.T) {
	e := mustEvent(t, map[string]interface{}{
		"event_type": "process",
		"data": map[string]interface{}{
			"name": "powershell.exe",
		},
	})
	if isAgentSelfEvent(e) {
		t.Fatal("event without parent fields must not be flagged")
	}
}

func TestIsAgentSelfEvent_NilSafe(t *testing.T) {
	if isAgentSelfEvent(nil) {
		t.Fatal("nil event must not be flagged")
	}
}
