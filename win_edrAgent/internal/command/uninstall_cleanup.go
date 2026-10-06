package command

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Markers written into the hosts file by the agent. Kept in sync with
// installer.hostsComment (C2 mapping) and blockDomain (sinkhole blocks).
const (
	hostsFilePath       = `C:\Windows\System32\drivers\etc\hosts`
	hostsC2Marker       = "# EDR C2"
	hostsBlockBeginMark = "# EDR_BLOCK_BEGIN "
	hostsBlockEndMark   = "# EDR_BLOCK_END "
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
	if data, err := os.ReadFile(hostsFilePath); err != nil {
		h.logger.Warnf("[UNINSTALL] Read hosts file failed: %v", err)
	} else if cleaned, changed := stripEDRHostsEntries(string(data)); changed {
		if err := os.WriteFile(hostsFilePath, []byte(cleaned), 0644); err != nil {
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

// stripEDRHostsEntries removes the lines the agent added to the hosts file:
// the "# EDR C2" server mapping and every "# EDR_BLOCK_BEGIN/END <domain>"
// sinkhole block. Inside a block only the agent's own "127.0.0.1 <domain>"
// line is dropped, so any user content that ended up between the markers is
// preserved. Returns the cleaned content and whether anything changed.
func stripEDRHostsEntries(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	changed := false
	blockDomain := ""

	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case strings.Contains(line, hostsC2Marker):
			changed = true
		case strings.HasPrefix(t, hostsBlockBeginMark):
			blockDomain = strings.TrimSpace(strings.TrimPrefix(t, hostsBlockBeginMark))
			changed = true
		case strings.HasPrefix(t, hostsBlockEndMark):
			blockDomain = ""
			changed = true
		case blockDomain != "" && strings.EqualFold(strings.Join(strings.Fields(t), " "), "127.0.0.1 "+blockDomain):
			changed = true
		default:
			out = append(out, line)
		}
	}
	if !changed {
		return content, false
	}
	return strings.Join(out, "\n"), true
}
