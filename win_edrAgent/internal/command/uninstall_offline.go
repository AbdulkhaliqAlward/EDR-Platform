package command

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/edr-platform/win-agent/internal/edrhosts"
	"github.com/edr-platform/win-agent/internal/logging"
)

// OfflineRevertHostArtifacts reverts the host-level changes the agent may have
// made, for the OFFLINE uninstall path (SYSTEM stage2), where no running
// command Handler exists. It restores outbound network, removes EDR firewall
// rules, strips EDR hosts entries, and removes an EDR-installed Sysmon.
//
// It shares the hosts-parsing (edrhosts) and firewall-rule names
// (removeIsolationRules) with the online cleanup, so there is one source of
// truth for each. Every step is best-effort and logged; one failure never
// stops the rest.
func OfflineRevertHostArtifacts(logger *logging.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// ── 1. Restore outbound-allow firewall policy ───────────────────────────
	// If the machine was isolated when uninstalled, the policy is
	// blockinbound,blockoutbound; without this the host stays cut off.
	if out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,allowoutbound").CombinedOutput(); err != nil {
		logger.Errorf("[UNINSTALL] Restore firewall policy failed: %v: %s", err, trim(string(out), 300))
	} else {
		logger.Info("[UNINSTALL] Firewall policy restored to blockinbound,allowoutbound")
	}

	// ── 2. Remove EDR firewall rules ────────────────────────────────────────
	removeIsolationRules() // EDR_C2_*, EDR_DNS_ALLOW, EDR_LOOPBACK_ALLOW (+ legacy)
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name=EDR_Isolation_Whitelist").Run()
	if out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -DisplayName 'EDR_BLOCK_IP_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule").CombinedOutput(); err != nil {
		logger.Warnf("[UNINSTALL] Removing EDR_BLOCK_IP_* rules failed: %v: %s", err, trim(string(out), 300))
	}
	logger.Info("[UNINSTALL] EDR firewall rules removed")

	// ── 3. Hosts file: C2 mapping + domain sinkhole blocks ──────────────────
	if data, err := os.ReadFile(edrhosts.Path); err != nil {
		logger.Warnf("[UNINSTALL] Read hosts file failed: %v", err)
	} else if cleaned, changed := edrhosts.StripEntries(string(data)); changed {
		if err := os.WriteFile(edrhosts.Path, []byte(cleaned), 0644); err != nil {
			logger.Errorf("[UNINSTALL] Write hosts file failed: %v", err)
		} else {
			logger.Info("[UNINSTALL] EDR entries removed from hosts file")
		}
	}

	// ── 4. Sysmon — only if this agent installed it ─────────────────────────
	if fileExists(sysmonInstalledByEDRMarker()) {
		_ = setEventChannelEnabled(ctx, sysmonChannel, false)
		if fileExists(sysmonExePath()) {
			if out, err := execCombined(ctx, sysmonExePath(), "-accepteula", "-u"); err != nil {
				logger.Errorf("[UNINSTALL] Sysmon removal failed: %v: %s", err, trim(out, 300))
			} else {
				logger.Info("[UNINSTALL] Sysmon (installed by EDR) uninstalled")
			}
		}
	} else if isSysmonServiceInstalled(ctx) {
		logger.Info("[UNINSTALL] Sysmon present but not installed by EDR — left in place")
	}
}
