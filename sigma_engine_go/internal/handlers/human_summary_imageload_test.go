package handlers

import (
	"strings"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
)

func TestHumanSummaryImageLoad(t *testing.T) {
	rule := "Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded"
	newAgent := &database.Alert{Category: "image_load", RuleTitle: rule, ContextData: map[string]interface{}{
		"event_type": "image_load",
		"data":       map[string]interface{}{"name": "dbghelp.dll", "process_name": "loader.exe", "ImageLoaded": `C:\Tools\dbghelp.dll`, "executable": `C:\Tools\loader.exe`},
	}}
	if s := generateHumanSummary(newAgent); s != `loader.exe loaded module "dbghelp.dll" (`+rule+`)` {
		t.Fatalf("summary %q", s)
	}
	// Older agents: process_name "unknown" and no image — never print "unknown" as the actor.
	oldAgent := &database.Alert{Category: "image_load", RuleTitle: rule, ContextData: map[string]interface{}{
		"event_type": "image_load",
		"data":       map[string]interface{}{"name": "dbghelp.dll", "process_name": "unknown", "ImageLoaded": `C:\Tools\dbghelp.dll`},
	}}
	if s := generateHumanSummary(oldAgent); strings.Contains(s, "unknown") || !strings.Contains(s, "dbghelp.dll") {
		t.Fatalf("summary %q", s)
	}
	// A placeholder name with a captured image uses the image.
	partial := &database.Alert{Category: "network_connection", RuleTitle: "x", ContextData: map[string]interface{}{
		"event_type": "network",
		"data":       map[string]interface{}{"process_name": "pid:4242", "Image": `C:\Users\a\evil.exe`},
	}}
	if s := generateHumanSummary(partial); !strings.HasPrefix(s, "evil.exe ") {
		t.Fatalf("summary %q", s)
	}
}
