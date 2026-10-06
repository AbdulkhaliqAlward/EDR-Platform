package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/edr-platform/win-agent/internal/command"
	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/installer"
	"github.com/edr-platform/win-agent/internal/logging"
	"github.com/edr-platform/win-agent/internal/protection"
	"github.com/edr-platform/win-agent/internal/security"
	"github.com/edr-platform/win-agent/internal/uninstalltoken"
)

// runUninstall is stage 1 of the offline uninstall (runs as the elevated
// Administrator who launched the downloaded binary). It verifies the
// server-signed, agent-bound token locally for immediate feedback, then — only
// on success — hands the token to the SYSTEM stage 2, which verifies it again
// before performing the actual removal.
func runUninstall(logger *logging.Logger, tokenVal string) {
	if strings.TrimSpace(EmbeddedUninstallPubKey) == "" {
		fmt.Fprintln(os.Stderr, "[X] This agent build does not support offline uninstall.")
		fmt.Fprintln(os.Stderr, "    Rebuild the agent from the dashboard (the build embeds the server's")
		fmt.Fprintln(os.Stderr, "    uninstall verification key), or use the dashboard's Uninstall command while online.")
		logger.Warn("[Uninstall] Rejected: no EmbeddedUninstallPubKey in this build")
		os.Exit(1)
	}
	if strings.TrimSpace(tokenVal) == "" {
		fmt.Fprintln(os.Stderr, "[X] No uninstall token provided.")
		fmt.Fprintln(os.Stderr, "    Generate one from the dashboard (device page → Generate uninstall token), then run:")
		fmt.Fprintln(os.Stderr, `      echo '<token>' | .\edr-agent.exe -uninstall -token-stdin`)
		os.Exit(1)
	}

	// This machine's server-assigned agent ID, taken ONLY from the enrolled
	// identity in the registry. Never guessed: a missing or unreadable identity
	// is reported as such instead of producing a misleading "wrong agent".
	agentID, err := resolveLocalAgentID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] %v\n", err)
		logger.Warnf("[Uninstall] Rejected: %v", err)
		os.Exit(1)
	}

	claims, err := uninstalltoken.Verify(EmbeddedUninstallPubKey, tokenVal, agentID, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] Uninstall token rejected: %v\n", err)
		if errors.Is(err, uninstalltoken.ErrWrongAgent) {
			fmt.Fprintf(os.Stderr, "    This device's agent ID is %s.\n", agentID)
			fmt.Fprintln(os.Stderr, "    Generate the token from THIS device's page in the dashboard (the IDs must match).")
		}
		logger.Warnf("[Uninstall] Token rejected for agent %s: %v", agentID, err)
		os.Exit(1)
	}
	logger.Infof("[Uninstall] Token verified for agent %s (expires %s) — scheduling removal",
		agentID, time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339))

	selfExe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] Cannot resolve own path: %v\n", err)
		os.Exit(1)
	}
	selfExe, _ = filepath.Abs(selfExe)

	// Hand the token to stage 2 through a private temp file (not the command
	// line: it is too long for schtasks /TR and would be visible there).
	tokenFile, err := writeUninstallTokenFile(tokenVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] Cannot prepare removal task: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[1/2] Uninstall token verified for this device.")
	fmt.Println("[2/2] Scheduling SYSTEM removal task...")
	if err := scheduleUninstallStage2AsSystem(selfExe, tokenFile); err != nil {
		_ = os.Remove(tokenFile)
		fmt.Fprintf(os.Stderr, "[X] Failed to schedule removal: %v\n", err)
		fmt.Fprintln(os.Stderr, "    Make sure you are running this from an elevated (Administrator) prompt.")
		logger.Errorf("[Uninstall] schedule stage2 failed: %v", err)
		os.Exit(1)
	}
	fmt.Println("      → Removal scheduled. The agent and its data will be removed shortly.")
	fmt.Println("      Verify after ~1 minute:  sc query EDRAgent   (should report it does not exist)")
	logger.Info("[Uninstall] SYSTEM stage2 scheduled")
	os.Exit(0)
}

// resolveLocalAgentID returns this machine's canonical agent ID from the
// enrolled identity stored in HKLM\SOFTWARE\EDR\Agent: the client certificate
// (same rule the server uses), falling back to the stored agent ID. Both are
// normalized ("agent-<UUID>" → "<UUID>"). It never falls back to defaults,
// which would yield a random ID.
func resolveLocalAgentID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\EDR\Agent`, registry.QUERY_VALUE)
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "", fmt.Errorf("access denied reading the agent configuration — run this from an elevated prompt (Run as Administrator)")
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return "", fmt.Errorf("no EDR agent configuration found in the registry — the agent does not appear to be installed on this machine")
	case err != nil:
		return "", fmt.Errorf("cannot open the agent configuration in the registry: %v", err)
	}
	k.Close()

	cfg, err := config.LoadFromRegistry()
	if err != nil {
		return "", fmt.Errorf("cannot read the agent configuration: %v", err)
	}
	if cfg == nil {
		return "", fmt.Errorf("the agent configuration is empty — the agent was never enrolled on this machine")
	}
	if id := uninstalltoken.AgentIDFromCertPEM(cfg.Certs.CertPEM); id != "" {
		return id, nil
	}
	if id := uninstalltoken.NormalizeAgentID(cfg.Agent.ID); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("the agent identity was not found — the agent does not appear to be enrolled")
}

// writeUninstallTokenFile stores the token in a new, uniquely named file in
// the current user's temp directory (created exclusively, 0600). Stage 2 reads
// and deletes it. Even if tampered with, it cannot help: stage 2 re-verifies
// the signature.
func writeUninstallTokenFile(token string) (string, error) {
	f, err := os.CreateTemp("", "edr_uninstall_token_*.txt")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.WriteString(strings.TrimSpace(token)); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return abs, nil
}

// scheduleUninstallStage2AsSystem registers and runs a one-shot SYSTEM task
// that invokes this same (downloaded) binary with -uninstall-stage2. Running
// from the downloaded location — not from C:\ProgramData\EDR — lets stage2
// delete the installed tree without locking its own image.
func scheduleUninstallStage2AsSystem(selfExe, tokenFile string) error {
	taskName := fmt.Sprintf("EDR_Uninstall_%d", time.Now().UnixNano())
	st := time.Now().Add(1 * time.Minute).Format("15:04")

	tr := fmt.Sprintf("\"%s\" -uninstall-stage2 -token-file \"%s\"", selfExe, tokenFile)
	if len(tr) > 261 {
		return fmt.Errorf("schtasks /TR too long (%d > 261) — move the downloaded binary to a shorter path (e.g. C:\\edr\\)", len(tr))
	}

	create := exec.Command("schtasks", "/Create", "/TN", taskName, "/RU", "SYSTEM", "/SC", "ONCE", "/ST", st, "/F", "/TR", tr)
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	run := exec.Command("schtasks", "/Run", "/TN", taskName)
	if out, err := run.CombinedOutput(); err != nil {
		_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
	return nil
}

// runUninstallStage2 is stage 2 (runs as SYSTEM via schtasks). It first
// re-verifies the uninstall token against this machine's identity — so the
// removal itself is always gated by a valid server-signed token — then stops
// the service, releases self-protections, reverts host artifacts, and removes
// the service registration, registry hive, Event Log source, and agent files.
func runUninstallStage2(logger *logging.Logger, tokenFile string) {
	const serviceName = installer.ServiceName
	logger.Info("[Uninstall] Stage2 (SYSTEM) started")

	// ── Gate: valid token required ──────────────────────────────────────────
	if strings.TrimSpace(tokenFile) == "" {
		logger.Warn("[Uninstall] Stage2 refused: no token file supplied")
		os.Exit(1)
	}
	raw, readErr := os.ReadFile(tokenFile)
	_ = os.Remove(tokenFile) // single use; remove regardless of outcome
	if readErr != nil || strings.TrimSpace(string(raw)) == "" {
		logger.Warnf("[Uninstall] Stage2 refused: token file unreadable or empty: %v", readErr)
		os.Exit(1)
	}
	agentID, err := resolveLocalAgentID()
	if err != nil {
		logger.Warnf("[Uninstall] Stage2 refused: %v", err)
		os.Exit(1)
	}
	if _, err := uninstalltoken.Verify(EmbeddedUninstallPubKey, string(raw), agentID, time.Now()); err != nil {
		logger.Warnf("[Uninstall] Stage2 refused: token rejected for agent %s: %v", agentID, err)
		os.Exit(1)
	}
	logger.Infof("[Uninstall] Stage2 token verified for agent %s — removing agent", agentID)

	// 1. Disable recovery so the SCM does not relaunch the service we stop.
	_ = exec.Command("sc.exe", "failure", serviceName, "reset=", "0", "actions=", "//").Run()

	// 2. Stop the service and wait for it to actually stop (watchdog dies with it).
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	waitForServiceStopped(logger, serviceName, 40*time.Second)

	// 3. Release self-protections (ownership/ACLs) so files + registry delete cleanly.
	_ = protection.RestoreServiceDACL(serviceName)
	_ = protection.RestoreServiceRegistryKey(serviceName)
	_ = protection.RestoreAgentRegistryKey()
	_ = security.RestoreAgentDirectoriesACL(config.DefaultConfig().DataDirectoriesToHarden())

	// 4. Revert host-level changes (firewall policy + rules, hosts, Sysmon).
	command.OfflineRevertHostArtifacts(logger)

	// 5. Delete the service registration.
	_ = exec.Command("sc.exe", "delete", serviceName).Run()

	// 6. Remove registry: agent hive (config, identity, certs) + Event Log source.
	_ = exec.Command("reg", "delete", `HKLM\SOFTWARE\EDR`, "/f").Run()
	_ = exec.Command("reg", "delete",
		`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\`+serviceName, "/f").Run()

	// 7. Remove all agent files. We run from the downloaded binary (outside this
	//    tree), so the installed edr-agent.exe is no longer in use after stop.
	removeAgentTree(logger, `C:\ProgramData\EDR`)

	logger.Info("[Uninstall] Stage2 complete — agent removed")
	fmt.Println("✓ EDR agent uninstalled.")
	os.Exit(0)
}

// waitForServiceStopped polls `sc query` until the service reports STOPPED or
// the service no longer exists, up to timeout. If it is still running it issues
// a targeted taskkill of the service's host process (not this process).
func waitForServiceStopped(logger *logging.Logger, serviceName string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
		if err != nil {
			// Service likely already deleted/unknown — treat as stopped.
			return
		}
		s := strings.ToUpper(string(out))
		if strings.Contains(s, "STOPPED") {
			return
		}
		time.Sleep(1 * time.Second)
	}
	logger.Warn("[Uninstall] Service did not stop in time — forcing its process to exit")
	// Kill the process hosting this service WITHOUT matching our own image name.
	_ = exec.Command("taskkill", "/F", "/FI", "SERVICES eq "+serviceName).Run()
	time.Sleep(2 * time.Second)
}

// removeAgentTree deletes the agent data directory, retrying once after a short
// pause in case a handle is still being released after service stop.
func removeAgentTree(logger *logging.Logger, dir string) {
	if err := os.RemoveAll(dir); err == nil {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			logger.Infof("[Uninstall] Removed %s", dir)
			return
		}
	}
	time.Sleep(3 * time.Second)
	if err := os.RemoveAll(dir); err != nil {
		logger.Warnf("[Uninstall] Could not fully remove %s: %v", dir, err)
	} else {
		logger.Infof("[Uninstall] Removed %s (second attempt)", dir)
	}
}
