//go:build windows
// +build windows

// Package pslogging manages the PowerShell Script Block Logging policy the
// agent relies on for PowerShell telemetry, and reverts it on uninstall.
package pslogging

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// Registry policy locations and the agent's own state key.
	psPolicyWindows = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
	psPolicyCore    = `SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging`
	agentStateKey   = `SOFTWARE\EDR\Agent`
	psMarkerValue   = "ScriptBlockLoggingEnabledByAgent"
)

// PolicyKeys are the Windows PowerShell 5.1 and PowerShell 7 policy keys.
var PolicyKeys = []string{psPolicyWindows, psPolicyCore}

// ── Script Block Logging policy ──────────────────────────────────────────────

// EnsureScriptBlockLogging enables Script Block Logging under key unless the
// administrator configured it explicitly (any existing value is respected,
// including an explicit 0). It records when the agent made the change.
func EnsureScriptBlockLogging(key string) (bool, error) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	if _, _, err := k.GetIntegerValue("EnableScriptBlockLogging"); err == nil {
		return false, nil // configured by the administrator / GPO: leave it
	}
	if err := k.SetDWordValue("EnableScriptBlockLogging", 1); err != nil {
		return false, err
	}
	if sk, _, err := registry.CreateKey(registry.LOCAL_MACHINE, agentStateKey, registry.QUERY_VALUE|registry.SET_VALUE); err == nil {
		prev, _, _ := sk.GetStringValue(psMarkerValue)
		_ = sk.SetStringValue(psMarkerValue, strings.Trim(prev+";"+key, ";"))
		sk.Close()
	}
	return true, nil
}

// RevertScriptBlockLogging removes the policy values the agent created
// (called on uninstall). Values configured by administrators are untouched.
func RevertScriptBlockLogging() {
	sk, err := registry.OpenKey(registry.LOCAL_MACHINE, agentStateKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer sk.Close()
	marker, _, err := sk.GetStringValue(psMarkerValue)
	if err != nil || marker == "" {
		return
	}
	for _, key := range strings.Split(marker, ";") {
		if key != psPolicyWindows && key != psPolicyCore {
			continue // only the two policy keys this agent manages
		}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE); err == nil {
			_ = k.DeleteValue("EnableScriptBlockLogging")
			k.Close()
		}
	}
	_ = sk.DeleteValue(psMarkerValue)
}
