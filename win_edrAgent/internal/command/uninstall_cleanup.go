package command

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/edr-platform/win-agent/internal/edrhosts"
)

// sysmonInstalledByEDRMarker is written by enableSysmon only when the agent
// performed a fresh Sysmon install. Uninstall removes Sysmon only when this
// marker exists, so a Sysmon deployment owned by the organisation is never
// touched.
func sysmonInstalledByEDRMarker() string {
	return sysmonToolDir() + `\installed_by_edr`
}

// cleanupHostArtifacts reverts every host-level change the agent's response
// actions may have left behind: network isolation (firewall policy + allow
// rules), IP block rules, hosts-file entries, and an EDR-installed Sysmon.
// It runs during a server-authorised uninstall, after the ACK has been sent
// and before the service tears down. Every step is best-effort so one
// failure never prevents the rest of the cleanup.
func (h *Handler) cleanupHostArtifacts() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// ── 1. Network isolation ────────────────────────────────────────────────
	// Isolation state is in-memory only, so also detect it from the rules on
	// disk (covers an agent restart while isolated). unisolateNetwork restores
	// the outbound-allow policy, stops the watchdog, and removes EDR_C2_* rules.
	h.mu.Lock()
	isolated := h.isIsolated
	h.mu.Unlock()
	if isolated || firewallRuleExists(ctx, "EDR_C2_GRPC_OUT") || firewallRuleExists(ctx, "EDR_Isolation_Whitelist") {
		if _, err := h.unisolateNetwork(ctx, map[string]string{}); err != nil {
			h.logger.Errorf("[UNINSTALL] Network isolation restore failed: %v", err)
		} else {
			h.logger.Info("[UNINSTALL] Network isolation removed — firewall policy restored")
		}
	}
	removeIsolationRules()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=EDR_Isolation_Whitelist").Run()

	// ── 2. IP block rules (EDR_BLOCK_IP_<dir>_<ip>) ─────────────────────────
	// Rule names embed the IP, so delete by prefix. netsh rule names are the
	// DisplayName in the NetSecurity module, which accepts wildcards.
	if out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -DisplayName 'EDR_BLOCK_IP_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule").CombinedOutput(); err != nil {
		h.logger.Warnf("[UNINSTALL] Removing EDR_BLOCK_IP_* rules failed: %v: %s", err, trim(string(out), 400))
	} else {
		h.logger.Info("[UNINSTALL] EDR_BLOCK_IP_* firewall rules removed")
	}

	// ── 3. Hosts file: C2 mapping + domain sinkhole blocks ──────────────────
	if data, err := os.ReadFile(edrhosts.Path); err != nil {
		h.logger.Warnf("[UNINSTALL] Read hosts file failed: %v", err)
	} else if cleaned, changed := edrhosts.StripEntries(string(data)); changed {
		if err := os.WriteFile(edrhosts.Path, []byte(cleaned), 0644); err != nil {
			h.logger.Errorf("[UNINSTALL] Write hosts file failed: %v", err)
		} else {
			h.logger.Info("[UNINSTALL] EDR entries removed from hosts file")
		}
	}

	// ── 4. Sysmon — only if this agent installed it ─────────────────────────
	if fileExists(sysmonInstalledByEDRMarker()) {
		if msg, err := h.disableSysmon(ctx, nil); err != nil {
			h.logger.Errorf("[UNINSTALL] Sysmon removal failed: %v", err)
		} else {
			h.logger.Infof("[UNINSTALL] %s", msg)
		}
	} else if isSysmonServiceInstalled(ctx) {
		h.logger.Info("[UNINSTALL] Sysmon present but not installed by EDR — left in place")
	}
}

// firewallRuleExists reports whether a Windows Firewall rule with the given
// name exists. netsh exits non-zero with "No rules match" when it does not.
func firewallRuleExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name="+name).Run() == nil
}
