// Package service provides Windows Service integration for the EDR Agent.
//go:build windows
// +build windows

package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/edr-platform/win-agent/internal/agent"
	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/enrollment"
	"github.com/edr-platform/win-agent/internal/logging"
	"github.com/edr-platform/win-agent/internal/protection"
	"github.com/edr-platform/win-agent/internal/security"
)

const (
	ServiceName        = "EDRAgent"
	ServiceDisplayName = "EDR Agent Service"
	ServiceDescription = "Endpoint Detection and Response Agent - Collects security events and provides threat protection"

)

// edrService implements the Windows service interface.
type edrService struct {
	configPath string         // path to config.yaml — loaded inside Execute()
	cfg        *config.Config // populated during Execute() after StartPending
	logger     *logging.Logger
	agent      *agent.Agent
}

// serverUninstallCh is the package-level signal used by the in-process C2
// command handler (command.UNINSTALL_AGENT) to tell the running SCM loop to
// tear protections down, schedule the SYSTEM cleanup task, and exit cleanly.
// A capacity of 1 makes the signal idempotent: repeated triggers collapse.
var serverUninstallCh = make(chan string, 1)

// TriggerServerUninstall is called from the command handler after it has
// received a server-authorised UNINSTALL_AGENT instruction. The service
// (running as SYSTEM) will perform the actual removal. The caller returns
// control to its command loop so SendCommandResult can ACK the server before
// the cleanup task fires.
func TriggerServerUninstall(reason string) {
	select {
	case serverUninstallCh <- reason:
	default:
		// A previous uninstall is already in flight — coalesce.
	}
}

// Execute is the Windows Service control handler.
//
// SCM Contract (critical):
//   - StartPending must be sent within ~30 s of Execute() being called.
//   - Running must be sent before any blocking I/O that could time out (TLS
//     handshakes, network calls, enrollment).
//   - If the agent cannot start after reporting Running, transition to
//     StopPending → return(false, non-zero) so the SCM logs a clean failure
//     rather than a 1053 "did not respond in a timely fashion" error.
//
// Startup sequence:
//  1. StartPending — acknowledge the SCM immediately.
//  2. Prepare the agent struct and wire callbacks (pure in-memory, cannot fail).
//  3. Running — satisfy the SCM contract BEFORE any network / TLS work.
//  4. Async goroutine:  CA fetch → enrollment → agent.Start()
//     On any failure: signal agentErrCh so the control loop can shut down cleanly.
func (s *edrService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	// ── Panic recovery: ensure SCM always gets a clean status transition ────
	// Without this, an unrecovered panic in Execute() would crash the service
	// process, causing an ungraceful termination visible as Error 1.
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Errorf("[SCM] PANIC recovered in Execute: %v", rec)
		}
	}()

	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue

	// ── 1. StartPending — satisfy SCM within the startup timeout window ────────
	changes <- svc.Status{State: svc.StartPending}

	// ── 1b. Load configuration ─────────────────────────────────────────────────
	// Priority: Registry (secure, SYSTEM-only) > YAML file (fallback, first boot only)
	//
	// After the first successful boot, config.yaml is migrated to the
	// protected Registry key and DELETED from disk. This ensures:
	//   - No plaintext config file visible to Administrators
	//   - Config survives file system tampering
	//   - Only SYSTEM can read the configuration
	var (
		cfg *config.Config
		err error
	)

	// Try Registry first (primary source after initial migration)
	cfg, err = config.LoadFromRegistry()
	if err != nil {
		s.logger.Warnf("[SCM] Registry config corrupted, falling back to YAML: %v", err)
		cfg = nil
	}
	if cfg != nil {
		s.logger.Info("[SCM] Config loaded from protected Registry (no YAML needed)")
		// Clean up any orphaned YAML from a crashed/aborted install
		if err := config.DeleteConfigFile(s.configPath); err == nil {
			s.logger.Info("[SCM] Cleaned up orphaned config.yaml from disk")
		}
		
		// Clean up any orphaned certificate files from an overlaid install
		_ = os.Remove(`C:\ProgramData\EDR\client.crt`)
		_ = os.Remove(`C:\ProgramData\EDR\private.key`)
		_ = os.Remove(`C:\ProgramData\EDR\ca-chain.crt`)
	} else {
		// Fallback: load from YAML file (first boot / fresh install)
		cfg, err = config.Load(s.configPath)
		if err != nil {
			s.logger.Errorf("[SCM] Failed to load configuration from %s: %v", s.configPath, err)
			changes <- svc.Status{State: svc.StopPending}
			return false, 2 // service-specific error code 2 = config load failure
		}
		s.logger.Infof("[SCM] Config loaded from YAML file: %s", s.configPath)

		// Migrate to Registry and delete YAML file
		if err := cfg.SaveToRegistry(); err != nil {
			s.logger.Warnf("[SCM] Failed to migrate config to Registry: %v", err)
		} else {
			s.logger.Info("[SCM] Config migrated to protected Registry")
			// Delete the plaintext YAML file — no longer needed
			if err := config.DeleteConfigFile(s.configPath); err != nil {
				s.logger.Warnf("[SCM] Failed to delete config YAML: %v", err)
			} else {
				s.logger.Info("[SCM] config.yaml deleted from disk (migrated to Registry)")
			}
		}
	}

	s.cfg = cfg
	s.logger.SetLevel(cfg.Logging.Level)
	s.logger.Infof("[SCM] Config active: server=%s agent=%s", cfg.Server.Address, cfg.Agent.ID)

	// ── 2. Prepare agent (pure in-memory, cannot fail) ────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.agent, err = agent.New(s.cfg, s.logger)
	if err != nil {
		s.logger.Errorf("[SCM] Failed to construct agent: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return false, 3 // service-specific error code 3 = agent init failure
	}

	s.agent.SetConfigFilePath(s.configPath)
	s.agent.SetRestartInfo(s.configPath)
	s.agent.SetConfigUpdateHandler(s.agent.UpdateConfig)

	// Wire the server-authorised uninstall hook. When an UNINSTALL_AGENT
	// command arrives, the command handler calls this function, which signals
	// the SCM control loop (below) via serverUninstallCh. The command handler
	// returns SUCCESS so SendCommandResult can ACK the server BEFORE the
	// SYSTEM cleanup task stops the service.
	s.agent.SetUninstallHook(func(reason string) error {
		TriggerServerUninstall(reason)
		return nil
	})

	// ── 3. Running — must be sent BEFORE any network / TLS / enrollment work ──
	// This satisfies the SCM contract. All subsequent work is async.
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.logger.Info("[SCM] Service reported Running — starting async enrollment + agent")
	s.logger.Infof("[SCM] Config path: %s", s.configPath)

	// ── Anti-Tamper Layer 1: Process DACL ─────────────────────────────────
	// Prevents taskkill, Task Manager, TerminateProcess from non-SYSTEM.
	// Must be called AFTER Running is reported (so SCM doesn't timeout).
	if err := protection.ProtectProcess(); err != nil {
		s.logger.Warnf("[SCM] Process self-protection failed (non-fatal): %v", err)
	} else {
		s.logger.Info("[SCM] Process self-protection enabled — tamper-resistant")
	}

	// NOTE: Anti-tamper layers 2-5 are applied ONLY after successful enrollment
	// and agent startup. This prevents a failed enrollment from leaving the host
	// in a half-hardened state (service stops, but directories/registry are locked).

	// ── Continuous Protection Watchdog: Process DACL ──────────────────
	// Re-applies process DACL every 10 seconds. If an attacker manages to
	// remove the DACL (e.g., via a SYSTEM-level tool), this goroutine
	// will restore it within 10 seconds.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := protection.ProtectProcess(); err != nil {
					s.logger.Warnf("[WATCHDOG] Process DACL re-apply failed: %v", err)
				}
			}
		}
	}()
	s.logger.Info("[SCM] Process DACL watchdog started (re-apply every 10s)")

	// ── Continuous Protection Watchdog: Registry Integrity ────────────
	// Checks every 5 seconds that the service registry key AND agent config
	// key still exist and are hardened. Re-applies if tampered.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Re-harden service registry keys (all ControlSets)
				_ = protection.HardenServiceRegistryKey(ServiceName)
				// Re-harden agent config registry key
				_ = protection.HardenAgentRegistryKey()
				// Re-apply NTFS ACLs if an admin reset icacls / ownership
				if s.cfg != nil {
					_ = security.HardenAgentDirectoriesExclusive(s.cfg.DataDirectoriesToHarden(), nil)
				}
			}
		}
	}()
	s.logger.Info("[SCM] Registry + directory integrity watchdog started (every 5s)")

	// ── Save critical config to protected Registry ───────────────────
	// This runs after config is loaded, providing a tamper-proof backup.
	go func() {
		// Wait for config to be fully loaded (after enrollment)
		time.Sleep(15 * time.Second)
		if s.cfg != nil {
			if err := protection.SaveCriticalConfig(
				s.cfg.Server.Address,
				s.cfg.Agent.ID,
				s.cfg.Certs.CAPath,
				s.cfg.Certs.CertPath,
				s.cfg.Certs.KeyPath,
			); err != nil {
				s.logger.Warnf("[SCM] Failed to save critical config to registry: %v", err)
			} else {
				s.logger.Info("[SCM] Critical config backed up to protected registry")
				_ = protection.HardenAgentRegistryKey()
			}
		}
	}()

	// agentErrCh carries the outcome of the async startup sequence.
	// A nil value means the agent is running; a non-nil value means it failed.
	agentErrCh := make(chan error, 1)

	// ── 4. Async startup goroutine ─────────────────────────────────────────────
	go func() {
		// 4a. Provision CA certificate — embedded if available, else HTTP fetch
		if !s.cfg.Server.Insecure && s.cfg.Certs.CAPath != "" {
			// Skip if CA cert is already loaded from the Registry
			if len(s.cfg.Certs.CACertPEM) == 0 {
				if err := enrollment.EnsureCACertificate(s.cfg.Server.Address, s.cfg.Certs.CAPath, s.logger); err != nil {
					s.logger.Warnf("[SCM] CA provisioning failed (using existing cert if present): %v", err)
				}
			} else {
				s.logger.Info("[SCM] CA certificate already loaded from Registry (skipping disk file provision)")
			}
		}

		// 4b. Enrollment — TLS to C2. Transient errors (server down, refused, etc.)
		// are retried so the SCM stays Running; only fatal errors stop the service.
		const enrollRetryInterval = 30 * time.Second
		for {
			if ctx.Err() != nil {
				s.logger.Infof("[SCM] Enrollment cancelled: %v", ctx.Err())
				agentErrCh <- ctx.Err()
				return
			}
			err := ensureEnrolled(s.cfg, s.logger, s.configPath)
			if err == nil {
				break
			}
			if enrollment.IsFatalEnrollmentError(err) {
				s.logger.Errorf("[SCM] Enrollment failed (fatal) — service will stop: %v", err)
				agentErrCh <- err
				cancel()
				return
			}
			s.logger.Warnf("[SCM] Enrollment will retry in %s: %v", enrollRetryInterval, err)
			select {
			case <-ctx.Done():
				agentErrCh <- ctx.Err()
				return
			case <-time.After(enrollRetryInterval):
			}
		}

		// 4c. Start the agent collectors and gRPC pipeline.
		if err := s.agent.Start(ctx); err != nil {
			s.logger.Errorf("[SCM] Agent start failed — service will stop: %v", err)
			agentErrCh <- err
			cancel()
			return
		}

		agentErrCh <- nil // signal: agent is live
	}()

	// ── 5. Control loop — handle SCM commands + startup failures ───────────────
	var startupDone bool
	for {
		select {
		case err := <-agentErrCh:
			startupDone = true
			if err != nil {
			// Startup failed: tell SCM we are stopping with an error code
				// so it records a proper "service terminated unexpectedly" event
				// instead of a confusing 1053 timeout.
				s.logger.Errorf("[SCM] Async startup failed: %v — transitioning to Stopped", err)
				changes <- svc.Status{State: svc.StopPending}
				// errno 1 → service-specific error, visible in Windows Event Log
				return false, 1
			}
			s.logger.Info("[SCM] Agent startup complete — fully operational")
			// Now that enrollment succeeded and the agent is live, apply tamper layers.
			s.applyPostEnrollHardening(ctx)

		case reason := <-serverUninstallCh:
			s.logger.Infof("[SCM] Server-issued uninstall received (reason=%q) — tearing down protections", reason)
			changes <- svc.Status{State: svc.StopPending}

			// Stop the integrity watchdogs first: they re-harden the registry
			// and directory ACLs every 5s and would undo the release below.
			cancel()

			// Release self-protections so the SYSTEM cleanup task can stop the
			// service and delete files. This is the same sequence that the
			// legacy uninstall-file watcher performed, minus the token dance.
			s.disableServiceRecovery()
			s.releaseSelfProtections()

			// Hand off the final "stop service + delete binary + remove
			// ProgramData\EDR" to a SYSTEM scheduled task so that the cleanup
			// outlives this process after Execute() returns.
			if err := scheduleSystemCleanupTask(reason); err != nil {
				s.logger.Errorf("[SCM] Failed to schedule SYSTEM cleanup task: %v", err)
			} else {
				s.logger.Info("[SCM] SYSTEM cleanup task scheduled — service will exit shortly")
			}

			if startupDone && s.agent != nil {
				done := make(chan struct{})
				go func() {
					s.agent.Stop()
					close(done)
				}()
				select {
				case <-done:
					s.logger.Info("[SCM] Agent stopped gracefully for uninstall")
				case <-time.After(30 * time.Second):
					s.logger.Warn("[SCM] Agent stop timed out after 30s")
				}
			}
			return false, 0

		case c, ok := <-r:
			if !ok {
				return false, 0
			}
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				s.logger.Info("[SCM] Stop/Shutdown requested")
				changes <- svc.Status{State: svc.StopPending}
				cancel()

				// Only try to stop the agent if it actually started.
				if startupDone && s.agent != nil {
					done := make(chan struct{})
					go func() {
						s.agent.Stop()
						close(done)
					}()
					select {
					case <-done:
						s.logger.Info("[SCM] Agent stopped gracefully")
					case <-time.After(30 * time.Second):
						s.logger.Warn("[SCM] Agent stop timed out after 30s")
					}
				}
				return false, 0

			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				s.logger.Info("[SCM] Service paused")

			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				s.logger.Info("[SCM] Service resumed")

			default:
				s.logger.Warnf("[SCM] Unexpected control request: %d", c.Cmd)
			}
		}
	}

	// Unreachable: for-select loop returns internally.
}

// Run starts the service.
//
// configPath is loaded inside Execute() (not here) so that svc.Run()
// registers the service handler with the SCM before any config I/O.
// This prevents "Error 1: Incorrect function" if config loading fails.
func Run(configPath string, logger *logging.Logger) error {
	logger.Infof("Initializing Windows Service (config=%s)...", configPath)

	// Check if running as a service
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("failed to check if running as service: %w", err)
	}

	if !isService {
		return fmt.Errorf("not running as a Windows service")
	}

	// Run the service — config loading is deferred to Execute().
	err = svc.Run(ServiceName, &edrService{
		configPath: configPath,
		logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("service run failed: %w", err)
	}

	return nil
}

// ensureEnrolled is a thin wrapper over enrollment.EnsureEnrolled used by Execute()
// to perform full certificate bootstrap inside the async startup goroutine,
// AFTER the SCM has already received svc.Running.
func ensureEnrolled(cfg *config.Config, logger *logging.Logger, configPath string) error {
	return enrollment.EnsureEnrolled(cfg, logger, configPath)
}

// disableServiceRecovery clears the service's recovery actions so the SCM
// does not auto-restart it after we exit Execute(). Must run before the
// service stops, otherwise a hardened new instance will immediately replace
// the one being removed.
func (s *edrService) disableServiceRecovery() {
	scm, err := mgr.Connect()
	if err != nil {
		s.logger.Warnf("[UNINSTALL] SCM connect for recovery disable failed: %v", err)
		return
	}
	defer scm.Disconnect()

	svcHandle, err := scm.OpenService(ServiceName)
	if err != nil {
		s.logger.Warnf("[UNINSTALL] Open service for recovery disable failed: %v", err)
		return
	}
	defer svcHandle.Close()

	noRestart := []mgr.RecoveryAction{
		{Type: mgr.NoAction, Delay: 0},
		{Type: mgr.NoAction, Delay: 0},
		{Type: mgr.NoAction, Delay: 0},
	}
	if err := svcHandle.SetRecoveryActions(noRestart, 0); err != nil {
		s.logger.Warnf("[UNINSTALL] SetRecoveryActions failed: %v", err)
		return
	}
	s.logger.Info("[UNINSTALL] Recovery actions disabled — no auto-restart")
}

// releaseSelfProtections reverts every tamper-hardening layer applied in
// Execute() so a SYSTEM cleanup task can stop the service, delete files, and
// remove registry keys without running into ACCESS_DENIED.
func (s *edrService) releaseSelfProtections() {
	if err := protection.RestoreServiceDACL(ServiceName); err != nil {
		s.logger.Errorf("[UNINSTALL] RestoreServiceDACL failed: %v", err)
	} else {
		s.logger.Info("[UNINSTALL] Service DACL restored — Admin access re-enabled")
	}

	if err := protection.RestoreServiceRegistryKey(ServiceName); err != nil {
		s.logger.Errorf("[UNINSTALL] RestoreServiceRegistryKey failed: %v", err)
	} else {
		s.logger.Info("[UNINSTALL] Service registry key DACL restored")
	}

	if err := protection.RestoreAgentRegistryKey(); err != nil {
		s.logger.Errorf("[UNINSTALL] RestoreAgentRegistryKey failed: %v", err)
	} else {
		s.logger.Info("[UNINSTALL] Agent config registry key DACL restored")
	}

	if s.cfg != nil {
		if err := security.RestoreAgentDirectoriesACL(s.cfg.DataDirectoriesToHarden()); err != nil {
			s.logger.Warnf("[UNINSTALL] RestoreAgentDirectoriesACL: %v", err)
		} else {
			s.logger.Info("[UNINSTALL] Agent data directory ACLs restored for cleanup")
		}
	}
}

func (s *edrService) applyPostEnrollHardening(ctx context.Context) {
	// ── Anti-Tamper Layer 2: Service DACL Hardening ────────────────────────
	if err := protection.HardenServiceDACL(ServiceName); err != nil {
		s.logger.Warnf("[SCM] Service DACL hardening failed (non-fatal): %v", err)
	} else {
		s.logger.Info("[SCM] Service DACL hardened — only SYSTEM can stop/delete")
	}

	// ── Anti-Tamper Layer 3: Registry Key Protection ───────────────────
	if err := protection.HardenServiceRegistryKey(ServiceName); err != nil {
		s.logger.Warnf("[SCM] Registry key hardening failed (non-fatal): %v", err)
	} else {
		s.logger.Info("[SCM] Service registry keys hardened (all ControlSets) — reg delete blocked")
	}

	// ── Anti-Tamper Layer 4: Agent Config Registry Protection ─────────
	if err := protection.HardenAgentRegistryKey(); err != nil {
		s.logger.Warnf("[SCM] Agent registry key hardening failed (non-fatal): %v", err)
	} else {
		s.logger.Info("[SCM] Agent config registry hardened — SYSTEM full, Admin read-only")
	}

	// ── Anti-Tamper Layer 5: NTFS — SYSTEM-only on agent data dirs + binary ─
	if s.cfg != nil {
		if err := security.HardenAgentDirectoriesExclusive(s.cfg.DataDirectoriesToHarden(), s.logger); err != nil {
			s.logger.Warnf("[SCM] Agent directory hardening failed (non-fatal): %v", err)
		} else {
			s.logger.Info("[SCM] Agent data directories hardened (SYSTEM-only, uninstall restores ACLs)")
		}
	}

	// ── Continuous Protection Watchdog: Registry Integrity ────────────
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = protection.HardenServiceRegistryKey(ServiceName)
				_ = protection.HardenAgentRegistryKey()
				if s.cfg != nil {
					_ = security.HardenAgentDirectoriesExclusive(s.cfg.DataDirectoriesToHarden(), nil)
				}
			}
		}
	}()
	s.logger.Info("[SCM] Registry + directory integrity watchdog started (every 5s)")
}

// scheduleSystemCleanupTask runs a one-shot SYSTEM scheduled task that waits
// for this service process to exit, then removes everything the install
// created: the SCM registration, HKLM\SOFTWARE\EDR (config, identity and
// certificates), the EDRAgent Event Log source, and C:\ProgramData\EDR.
// Host-level response artifacts (firewall, hosts, Sysmon) were already
// reverted in-process by the command handler before this point.
//
// The script lives in the SYSTEM temp directory, not under ProgramData\EDR,
// because cmd.exe reads batch files incrementally and the script deletes that
// directory. It deletes itself when done. The task definition is removed right
// after /Run so no EDR_ServerUninstall_* task remains (same as UPDATE_AGENT).
func scheduleSystemCleanupTask(reason string) error {
	stamp := time.Now().UnixNano()
	taskName := fmt.Sprintf("EDR_ServerUninstall_%d", stamp)
	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("edr_uninstall_%d.cmd", stamp))

	// O_EXCL: never write into a file someone else pre-created at this path,
	// since the script runs as SYSTEM.
	f, err := os.OpenFile(scriptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create cleanup script: %w", err)
	}
	if _, err := f.WriteString(buildUninstallCleanupScript()); err != nil {
		_ = f.Close()
		_ = os.Remove(scriptPath)
		return fmt.Errorf("write cleanup script: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(scriptPath)
		return fmt.Errorf("close cleanup script: %w", err)
	}

	tr := "cmd /c " + scriptPath
	if len(tr) > 261 {
		_ = os.Remove(scriptPath)
		return fmt.Errorf("schtasks /TR too long (%d > 261)", len(tr))
	}
	runAt := time.Now().Add(90 * time.Second).Format("15:04")
	create := exec.Command("schtasks", "/Create", "/TN", taskName, "/RU", "SYSTEM", "/SC", "ONCE", "/ST", runAt, "/F", "/TR", tr)
	out, err := create.CombinedOutput()
	if err != nil {
		_ = os.Remove(scriptPath)
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	run := exec.Command("schtasks", "/Run", "/TN", taskName)
	if out, err := run.CombinedOutput(); err != nil {
		_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
		_ = os.Remove(scriptPath)
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
	_ = reason // currently only logged by the caller; reserved for audit trail
	return nil
}

// buildUninstallCleanupScript returns the batch script executed by the SYSTEM
// cleanup task. Delays use ping rather than timeout.exe, which exits
// immediately when the task has no interactive console input.
func buildUninstallCleanupScript() string {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("setlocal EnableExtensions\r\n")
	b.WriteString(":: Grace period: let the service finish its own shutdown\r\n")
	b.WriteString("ping -n 6 127.0.0.1 >nul\r\n")
	b.WriteString(":: Disable SCM recovery so the service is not restarted, then stop it\r\n")
	b.WriteString("sc failure " + ServiceName + " reset= 0 actions= // >nul 2>&1\r\n")
	b.WriteString("sc stop " + ServiceName + " >nul 2>&1\r\n")
	b.WriteString(":: Wait up to ~45s for the agent process to exit, then force it\r\n")
	b.WriteString("set /a TRIES=0\r\n")
	b.WriteString(":WAIT_LOOP\r\n")
	b.WriteString("tasklist /FI \"IMAGENAME eq edr-agent.exe\" 2>nul | find /i \"edr-agent.exe\" >nul\r\n")
	b.WriteString("if errorlevel 1 goto PROC_DEAD\r\n")
	b.WriteString("set /a TRIES+=1\r\n")
	b.WriteString("if %TRIES% GEQ 15 (\r\n")
	b.WriteString("    taskkill /F /IM edr-agent.exe >nul 2>&1\r\n")
	b.WriteString("    ping -n 4 127.0.0.1 >nul\r\n")
	b.WriteString("    goto PROC_DEAD\r\n")
	b.WriteString(")\r\n")
	b.WriteString("ping -n 4 127.0.0.1 >nul\r\n")
	b.WriteString("goto WAIT_LOOP\r\n")
	b.WriteString(":PROC_DEAD\r\n")
	b.WriteString(":: Service registration, agent registry (config, identity, certificates), Event Log source\r\n")
	b.WriteString("sc delete " + ServiceName + " >nul 2>&1\r\n")
	b.WriteString("reg delete \"HKLM\\SOFTWARE\\EDR\" /f >nul 2>&1\r\n")
	b.WriteString("reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + ServiceName + "\" /f >nul 2>&1\r\n")
	b.WriteString(":: Agent files: binary, logs, queue, quarantine, signatures, tools\r\n")
	b.WriteString("rmdir /s /q \"C:\\ProgramData\\EDR\" >nul 2>&1\r\n")
	b.WriteString("if exist \"C:\\ProgramData\\EDR\" (\r\n")
	b.WriteString("    ping -n 6 127.0.0.1 >nul\r\n")
	b.WriteString("    rmdir /s /q \"C:\\ProgramData\\EDR\" >nul 2>&1\r\n")
	b.WriteString(")\r\n")
	b.WriteString(":: Delete this script\r\n")
	b.WriteString("(goto) 2>nul & del /f /q \"%~f0\"\r\n")
	return b.String()
}

// ServiceExists checks if EDRAgent is registered in the SCM using minimal
// permissions (SERVICE_QUERY_STATUS). This works even when the service DACL
// is hardened, unlike mgr.OpenService() which requires SERVICE_ALL_ACCESS.
func ServiceExists() bool {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scm)
	svcNamePtr, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(scm, svcNamePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(h)
	return true
}

// Install installs the Windows service. The agent no longer carries an
// uninstall secret — removal is a server-authorised C2 action — so no token
// state is persisted here.
func Install() error {
	// ── Pre-flight Check ────────────────────────────────────────────────
	// Check if service already exists BEFORE attempting any file operations.
	// If it does, we return an 'already exists' error immediately so the caller
	// (runInstall) can cleanly stop and uninstall it. This prevents "Access Denied"
	// and "File in use" errors when trying to overwrite a running agent binary.
	if ServiceExists() {
		return fmt.Errorf("service %s already exists", ServiceName)
	}
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	srcPath, err = filepath.Abs(srcPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// ── Create required directories (including secure bin dir) ────────────
	dirs := []string{
		"C:\\ProgramData\\EDR",
		"C:\\ProgramData\\EDR\\bin",
		"C:\\ProgramData\\EDR\\logs",
		"C:\\ProgramData\\EDR\\queue",
		"C:\\ProgramData\\EDR\\quarantine",
	}
	for _, dir := range dirs {
		os.MkdirAll(dir, 0700)
	}

	// ── Relocate EXE to secure path ──────────────────────────────────────
	// Copy the agent binary to C:\ProgramData\EDR\bin\ which will be
	// protected by SYSTEM-only DACL. The service is registered to run from
	// this secure path, so even if the original download is deleted, the
	// agent survives reboots.
	dstPath := filepath.Join("C:\\ProgramData\\EDR\\bin", "edr-agent.exe")
	if !strings.EqualFold(srcPath, dstPath) {
		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy agent to secure path: %w", err)
		}
		fmt.Printf("      Agent binary secured: %s\n", dstPath)
	}

	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// ── Register service from the SECURE path (not from Downloads!) ──────
	s, err := m.CreateService(ServiceName, dstPath, mgr.Config{
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
	},
		// SCM execution is auto-detected in cmd/agent/main.go via svc.IsWindowsService().
		// Passing -service here causes the process to exit before svc.Run in some
		// environments, leading to SCM error 7023: "Incorrect function".
		"-config", `C:\ProgramData\EDR\config.yaml`,
	)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Configure recovery options (restart on failure)
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 0},
	}
	if err := s.SetRecoveryActions(recoveryActions, 24*60*60); err != nil {
		fmt.Printf("Warning: failed to set recovery actions: %v\n", err)
	}

	// Create event log source
	if err := eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		fmt.Printf("Warning: failed to create event log source: %v\n", err)
	}

	// NOTE: HardenAgentRegistryKey is NOT called here because Install()
	// runs as Administrator, which cannot set OWNER=SYSTEM. The hardening
	// is applied in Execute() which runs as SYSTEM.

	return nil
}

// copyFile copies a file from src to dst, preserving content.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// Note: local, token-based Uninstall / ForceUninstall helpers were removed.
// The only supported removal path is an authenticated server-issued
// UNINSTALL_AGENT command processed by the command handler, which calls
// TriggerServerUninstall() above. The service itself then releases its
// protections and schedules a SYSTEM cleanup task to finish the removal.

// StartService opens a handle to the named service and issues a Start call.
// Blocks up to 10 s polling until the service reaches the Running state.
// This is used by the zero-touch installer after Install() to bring the
// service online without requiring a separate "net start" invocation.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		// "already running" is acceptable — caller may retry.
		if !isAlreadyRunning(err) {
			return fmt.Errorf("failed to start service: %w", err)
		}
		return nil
	}

	// Poll until Running (up to 30 s — first boot after install needs extra time
	// for config loading and agent construction inside Execute()).
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service status: %w", err)
		}
		if status.State == svc.Running {
			return nil
		}
		// If the service has already stopped, don't keep waiting
		if status.State == svc.Stopped {
			return fmt.Errorf("service stopped unexpectedly — check C:\\ProgramData\\EDR\\logs\\agent.log for details")
		}
	}

	return fmt.Errorf("service did not reach Running state within 30s — check C:\\ProgramData\\EDR\\logs\\agent.log")
}

// isAlreadyRunning returns true when the error message indicates the service
// is already in a running state (Windows error 1056).
func isAlreadyRunning(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already") ||
		strings.Contains(err.Error(), "1056")
}

// Status returns the current service status using minimal permissions
// (SERVICE_QUERY_STATUS). This works even when the service DACL is hardened,
// unlike mgr.OpenService() which requires SERVICE_ALL_ACCESS.
func Status() (svc.State, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to SCM: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcNamePtr, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(scm, svcNamePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, fmt.Errorf("service not found: %w", err)
	}
	defer windows.CloseServiceHandle(h)

	var needed uint32
	var buf [256]byte
	err = windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, &buf[0], uint32(len(buf)), &needed)
	if err != nil {
		return 0, fmt.Errorf("failed to query status: %w", err)
	}

	ssp := (*windows.SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0]))
	return svc.State(ssp.CurrentState), nil
}
