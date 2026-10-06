package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
// server-signed, agent-bound token locally, then — only on success — schedules
// the SYSTEM stage 2 that performs the actual removal.
func runUninstall(logger *logging.Logger, tokenVal, configPath string) {
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

	// Determine this machine's server-assigned agent ID (Registry first, as the
	// service stores it there; fall back to a YAML config if present).
	agentID := localAgentID(logger, configPath)
	if agentID == "" {
		fmt.Fprintln(os.Stderr, "[X] Could not determine this agent's ID. Is the agent installed, and are you running as Administrator?")
		logger.Warn("[Uninstall] Rejected: local agent ID unavailable")
		os.Exit(1)
	}

	claims, err := uninstalltoken.Verify(EmbeddedUninstallPubKey, tokenVal, agentID, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] Uninstall token rejected: %v\n", err)
		logger.Warnf("[Uninstall] Token rejected for agent %s: %v", agentID, err)
		os.Exit(1)
	}
	logger.Infof("[Uninstall] Token verified for agent %s (expires %s) — scheduling removal",
		claims.AgentID, time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339))

	selfExe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[X] Cannot resolve own path: %v\n", err)
		os.Exit(1)
	}
	selfExe, _ = filepath.Abs(selfExe)

	fmt.Println("[1/2] Uninstall token verified for this device.")
	fmt.Println("[2/2] Scheduling SYSTEM removal task...")
	if err := scheduleUninstallStage2AsSystem(selfExe); err != nil {
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

// localAgentID loads the server-assigned agent UUID from the protected Registry
// (Administrators have read access), falling back to a YAML config file.
func localAgentID(logger *logging.Logger, configPath string) string {
	if cfg, err := config.LoadFromRegistry(); err == nil && cfg != nil {
		if id := strings.TrimSpace(cfg.Agent.ID); id != "" {
			return id
		}
	} else if err != nil {
		logger.Debugf("[Uninstall] LoadFromRegistry failed: %v", err)
	}
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil && cfg != nil {
			return strings.TrimSpace(cfg.Agent.ID)
		}
	}
	return ""
}

// scheduleUninstallStage2AsSystem registers and runs a one-shot SYSTEM task
// that invokes this same (downloaded) binary with -uninstall-stage2. Running
// from the downloaded location — not from C:\ProgramData\EDR — lets stage2
// delete the installed tree without locking its own image.
func scheduleUninstallStage2AsSystem(selfExe string) error {
	taskName := fmt.Sprintf("EDR_Uninstall_%d", time.Now().UnixNano())
	st := time.Now().Add(1 * time.Minute).Format("15:04")

	tr := fmt.Sprintf("\"%s\" -uninstall-stage2", selfExe)
	if len(tr) > 261 {
		return fmt.Errorf("schtasks /TR too long (%d > 261) — move the downloaded binary to a shorter path", len(tr))
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

// runUninstallStage2 is stage 2 (runs as SYSTEM via schtasks). It stops the
// service, releases self-protections, reverts host artifacts, then removes the
// service registration, registry hive, Event Log source, and all agent files.
func runUninstallStage2(logger *logging.Logger) {
	const serviceName = installer.ServiceName
	logger.Info("[Uninstall] Stage2 (SYSTEM) started — removing agent")

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
