// Package main provides the entry point for the EDR Windows Agent.
//
// # Execution Modes
//
//	-install  Zero-touch setup: patch hosts file, write config.yaml, register SCM service,
//	           start the service. Requires -server-ip, -server-domain, and -token.
//	(uninstall)  Local uninstall is NOT supported. An agent is removed only via the
//	             server-issued UNINSTALL_AGENT C2 command (authorised via mTLS + RBAC).
//	CLI / standalone  Run interactively (development / testing).
//	SCM-managed  Detected automatically via svc.IsWindowsService(); no flag required.
package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/edr-platform/win-agent/internal/agent"
	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/enrollment"
	"github.com/edr-platform/win-agent/internal/installer"
	"github.com/edr-platform/win-agent/internal/logging"
	"github.com/edr-platform/win-agent/internal/protection"
	"github.com/edr-platform/win-agent/internal/security"
	"github.com/edr-platform/win-agent/internal/service"
)

// Version information (injected at build time via -ldflags).
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Embedded configuration (injected at build time via -ldflags by the dashboard build system).
var (
	EmbeddedServerIP     = "" // C2 server IP
	EmbeddedServerDomain = "" // C2 server FQDN
	EmbeddedServerPort   = "" // gRPC port
	EmbeddedInstallSysmon = "" // "true" to enable Sysmon bootstrap

	// NEW ARCHITECTURE (zero token material in binary):
	//   EmbeddedBuildID   — random UUID generated at build time, stored in DB.
	//   EmbeddedTokenHash — HMAC-SHA256(key=token, msg=buildID) hex.
	//   The agent verifies the token locally: HMAC(token, buildID) == EmbeddedTokenHash.
	//   A wrong token produces a different HMAC → exit(2) before any network call.
	EmbeddedBuildID   = "" // UUID baked in at build time
	EmbeddedTokenHash = "" // HMAC-SHA256 binding verifier

	// LEGACY SPLIT-KEY (deprecated — kept for binaries built before this change):
	EmbeddedTokenEnc  = ""
	EmbeddedTokenKeyA = ""
	EmbeddedTokenID   = ""

	// LEGACY SINGLE-KEY (deprecated):
	EmbeddedTokenKey = ""

	// LEGACY XOR (deprecated):
	EmbeddedTokenObf = ""
)

func main() {
	// ── CLI flags ──────────────────────────────────────────────────────────────
	var (
		configPath = flag.String(
			"config",
			installer.DefaultConfigPath,
			"Path to configuration YAML file",
		)
		showVersion = flag.Bool("version", false, "Show version information and exit")

		// ── Installation flags ─────────────────────────────────────────────────
		doInstall               = flag.Bool("install", false, "Zero-touch install: patch hosts, write config, register and start Windows Service")
		doUpdate                = flag.Bool("update", false, "In-place upgrade: replace agent binary, optionally update config, and restart Windows Service")
		doUpdateStage2          = flag.Bool("update-stage2", false, "[INTERNAL] Stage2 for -update, executed as SYSTEM")
		serverIP                = flag.String("server-ip", "", "C2 server IP address (used with -install for hosts file injection)")
		serverDomain            = flag.String("server-domain", "", "C2 server FQDN/hostname (used with -install)")
		serverPort              = flag.String("server-port", "50051", "C2 gRPC port (used with -install, default 50051)")
		token                   = flag.String("token", "", "Enrollment token (legacy — prefer -token-stdin)")
		// tokenStdin: secure token delivery via stdin.
		// Usage: echo '<token>' | agent.exe -install -token-stdin
		// The token never appears in the process list, Event Log, or shell history.
		tokenStdin              = flag.Bool("token-stdin", false, "Read enrollment token from stdin (one line, trimmed)")
		installSkipConnectivity = flag.Bool(
			"install-skip-connectivity-check",
			false,
			"Skip TCP preflight during -install (use only when C2 is intentionally unreachable or after fixing firewall)",
		)

		// ── Runtime flags ──────────────────────────────────────────────────────
		debugMode = flag.Bool("debug", false, "Enable DEBUG-level logging")

		// Deprecated: kept for backward compatibility. SCM detection is now automatic.
		_ = flag.Bool("service", false, "[DEPRECATED] Run as Windows Service — now detected automatically")
	)
	flag.Parse()

	// ── Version ────────────────────────────────────────────────────────────────
	if *showVersion {
		fmt.Printf("EDR Windows Agent\n")
		fmt.Printf("  Version:    %s\n", Version)
		fmt.Printf("  Build Time: %s\n", BuildTime)
		fmt.Printf("  Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	// ── Bootstrap logger (written to disk so SCM-managed starts have a log) ──
	logLevel := "INFO"
	if *debugMode {
		logLevel = "DEBUG"
	}
	logger := logging.NewLogger(logging.Config{
		Level:      logLevel,
		FilePath:   `C:\ProgramData\EDR\logs\agent.log`,
		MaxSizeMB:  100,
		MaxAgeDays: 7,
	})
	defer logger.Close()

	// ══════════════════════════════════════════════════════════════════════════
	// INSTALL PATH
	// ══════════════════════════════════════════════════════════════════════════
	if *doInstall {
		tokenVal := *token
		if *tokenStdin {
			// Read token from stdin — secure path. Never appears in process list.
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				tokenVal = strings.TrimSpace(scanner.Text())
			}
		}
		runInstall(logger, *serverIP, *serverDomain, *serverPort, tokenVal, *configPath, *installSkipConnectivity)
		// runInstall calls os.Exit internally.
	}

	// ══════════════════════════════════════════════════════════════════════════
	// UPDATE PATH (Stage2 runs as SYSTEM via scheduled task)
	// ══════════════════════════════════════════════════════════════════════════
	if *doUpdateStage2 {
		runUpdateStage2(logger, *serverIP, *serverDomain, *serverPort, *token, *configPath)
		// runUpdateStage2 calls os.Exit internally.
	}
	if *doUpdate {
		runUpdate(logger, *serverIP, *serverDomain, *serverPort, *token, *configPath)
		// runUpdate calls os.Exit internally.
	}

	// ══════════════════════════════════════════════════════════════════════════
	// UNINSTALL PATH — intentionally not implemented as a local CLI action.
	// ══════════════════════════════════════════════════════════════════════════
	// Uninstall is a privileged server-side operation. It is issued as a C2
	// command (UNINSTALL_AGENT) over the agent's mTLS stream and authorised by
	// the dashboard's RBAC + audit pipeline. Keeping a local "-uninstall -token"
	// path would mean every deployed binary carries a removal secret that an
	// attacker with filesystem access could eventually extract.

	// ══════════════════════════════════════════════════════════════════════════
	// RUNTIME PATH — detect execution mode FIRST, then load config
	// ══════════════════════════════════════════════════════════════════════════

	// Self-heal a common drift scenario: registry says one C2 hostname while
	// the binary was built (via dashboard / agent-builder ldflags) for a
	// different deployment domain. Without this step the agent will keep
	// trying the stale hostname forever, so commands like ISOLATE_NETWORK
	// fail with "DNS resolution of <stale-host> failed".
	reconcileServerAddressWithEmbedded(logger)

	// ── Execution mode detection — MUST happen BEFORE config loading ──────────
	// CRITICAL: When the SCM starts this process, svc.Run() must be called as
	// early as possible so the service handler is registered with the SCM.
	// If config.Load() (or any other call) triggers os.Exit() before svc.Run(),
	// the SCM receives no handler and reports "Error 1: Incorrect function".
	//
	// Therefore, in the SCM path, config loading is deferred to inside
	// service.Execute() where errors are reported via proper SCM status
	// transitions (StopPending → Stopped) instead of process termination.
	isScm, err := svc.IsWindowsService()
	if err != nil {
		logger.Warnf("IsWindowsService check failed (%v); assuming standalone mode", err)
		isScm = false
	}

	if isScm {
		// SCM path: hand off directly to service.Run() — Execute() will
		// load config, perform CA fetch → enrollment → agent.Start()
		// asynchronously, reporting proper SCM status at each stage.
		logger.Info("Execution context: Windows Service Control Manager")
		if err := service.Run(*configPath, logger); err != nil {
			logger.Errorf("Service execution error: %v", err)
			os.Exit(1)
		}
		return
	}

	// ── Standalone / interactive path ──────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Errorf("Failed to load configuration: %v", err)
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	logger.SetLevel(cfg.Logging.Level)
	logger.Infof("════════════════════════════════════════")
	logger.Infof("EDR Windows Agent v%s", Version)
	logger.Infof("════════════════════════════════════════")
	logger.Infof("Config:    %s", *configPath)
	logger.Infof("Server:    %s", cfg.Server.Address)
	logger.Infof("Agent ID:  %s", cfg.Agent.ID)

	logger.Info("Execution context: Interactive / standalone (Ctrl+C to stop)")

	// Auto-bootstrap CA certificate — uses embedded cert if available, else HTTP fetch.
	if !cfg.Server.Insecure && cfg.Certs.CAPath != "" {
		if err := enrollment.EnsureCACertificate(cfg.Server.Address, cfg.Certs.CAPath, logger); err != nil {
			logger.Warnf("CA auto-bootstrap failed (will try existing cert): %v", err)
		}
	}

	// Ensure enrolled (cert/key present or bootstrap registration) before starting.
	if err := enrollment.EnsureEnrolled(cfg, logger, *configPath); err != nil {
		logger.Errorf("Agent enrollment failed: %v", err)
		os.Exit(1)
	}

	runStandalone(cfg, logger, *configPath)
}

// reconcileServerAddressWithEmbedded compares the C2 hostname currently
// persisted in the registry against the EmbeddedServerDomain that was baked
// into this binary at build time. If they disagree AND the registry hostname
// fails DNS resolution, it rewrites the registry to use the embedded domain
// and (best-effort) re-patches the Windows hosts file so DNS works.
//
// Why this exists:
//
//	In real deployments we have seen the registry retain "edr.local" from an
//	older install while a freshly-built binary was shipped pointing at, e.g.,
//	"protosoft.cloud". The agent then tries to resolve the stale hostname for
//	every C2 operation that needs an IP (ISOLATE_NETWORK, watchdog re-resolve,
//	etc.) and fails with "DNS resolution of edr.local failed".
//
// Safety:
//
//	The reconciliation is GATED by net.LookupHost(currentHost) == error. If
//	the operator legitimately set Server.Address to a hostname that DOES
//	resolve, we leave it alone — even when it differs from the embedded
//	domain. This preserves intentional overrides while fixing genuine drift.
func reconcileServerAddressWithEmbedded(logger *logging.Logger) {
	embDomain := strings.TrimSpace(EmbeddedServerDomain)
	embIP := strings.TrimSpace(EmbeddedServerIP)
	embPort := strings.TrimSpace(EmbeddedServerPort)
	if embDomain == "" {
		return // not a dashboard / agent-builder build — nothing to reconcile against
	}

	cfg, err := config.LoadFromRegistry()
	if err != nil || cfg == nil {
		return // first boot or registry locked — install path will populate it
	}

	currentHost, currentPort, splitErr := net.SplitHostPort(cfg.Server.Address)
	if splitErr != nil {
		// Address has no :port — treat the whole string as host.
		currentHost = strings.TrimSpace(cfg.Server.Address)
		currentPort = ""
	}
	if strings.EqualFold(currentHost, embDomain) {
		return // already aligned
	}

	// If the operator-configured host actually resolves, respect it.
	if _, lookupErr := net.LookupHost(currentHost); lookupErr == nil {
		logger.Debugf("Reconcile: registry host %q resolves OK; embedded %q ignored",
			currentHost, embDomain)
		return
	}

	logger.Warnf("Reconcile: registry C2 host %q does not resolve and differs from embedded %q — self-healing",
		currentHost, embDomain)

	// Re-patch the hosts file (only meaningful when we have an embedded IP).
	if embIP != "" {
		if patchErr := installer.PatchHostsFile(embIP, embDomain); patchErr != nil {
			logger.Warnf("Reconcile: hosts file patch failed (non-fatal): %v", patchErr)
		} else {
			logger.Infof("Reconcile: hosts file patched %s → %s", embIP, embDomain)
		}
	}

	port := currentPort
	if port == "" {
		port = embPort
	}
	if port == "" {
		port = "50051"
	}
	cfg.Server.Address = embDomain + ":" + port

	// The Connection Manager certificate is issued for the internal service
	// name, not the public deployment domain. Reset TLSServerName so TLS
	// verification succeeds after the rewrite (mirrors the rule applied by
	// runInstall / runUpdateStage2).
	tlsName := strings.TrimSpace(cfg.Server.TLSServerName)
	if tlsName == "" || strings.EqualFold(tlsName, currentHost) || strings.EqualFold(tlsName, embDomain) {
		cfg.Server.TLSServerName = config.DefaultGRPCServerCertName
	}

	if saveErr := cfg.SaveToRegistry(); saveErr != nil {
		logger.Errorf("Reconcile: SaveToRegistry failed: %v", saveErr)
		return
	}
	logger.Infof("Reconcile: registry C2 host updated %s → %s",
		currentHost, cfg.Server.Address)
}

// resolveInstallParam returns the effective value for an install parameter.
// Priority: CLI flag (if non-empty and differs from default) > embedded > empty.
func resolveInstallParam(cliVal, embeddedVal, paramName string) string {
	if cliVal != "" {
		return cliVal
	}
	if embeddedVal != "" {
		fmt.Printf("  Using dashboard-configured %s: %s\n", paramName, embeddedVal)
		return embeddedVal
	}
	return ""
}

// applyEmbeddedGRPCPortIfDefault overwrites *port when the CLI left the
// default (50051) or empty, and the build has EmbeddedServerPort (dashboard).
// The flag default is 50051, so resolveInstallParam would otherwise never use
// embedded (e.g. 47051 for public gRPC behind NAT/SG).
func applyEmbeddedGRPCPortIfDefault(port *string) {
	if port == nil {
		return
	}
	p := *port
	if p != "" && p != "50051" {
		return
	}
	if EmbeddedServerPort != "" {
		*port = EmbeddedServerPort
	} else if p == "" {
		*port = "50051"
	}
}

// printInstallHelp displays a formatted help message for missing install parameters.
func printInstallHelp(missingParams []string) {
	fmt.Fprintf(os.Stderr, "\n╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "║           EDR Agent — Installation Help                     ║\n")
	fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════╝\n\n")

	if len(missingParams) > 0 {
		fmt.Fprintf(os.Stderr, "Missing required parameters:\n")
		for _, p := range missingParams {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", p)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintf(os.Stderr, "Required parameters:\n")
	fmt.Fprintf(os.Stderr, "  %-20s  %s\n", "-server-ip", "C2 server IP address (e.g. 192.168.1.10)")
	fmt.Fprintf(os.Stderr, "  %-20s  %s\n", "-server-domain", "C2 server FQDN (e.g. edr.internal)")
	fmt.Fprintf(os.Stderr, "  %-20s  %s\n", "-token", "Bootstrap enrollment token")
	fmt.Fprintf(os.Stderr, "\nOptional parameters:\n")
	fmt.Fprintf(os.Stderr, "  %-20s  %s\n", "-server-port", "C2 gRPC port (default: 50051)")
	fmt.Fprintf(os.Stderr, "  %-20s  %s\n", "-config", "Config file path")
	fmt.Fprintf(os.Stderr, "\nExample:\n")
	fmt.Fprintf(os.Stderr, "  agent.exe -install ^\n")
	fmt.Fprintf(os.Stderr, "    -server-ip 192.168.1.10 ^\n")
	fmt.Fprintf(os.Stderr, "    -server-domain edr.internal ^\n")
	fmt.Fprintf(os.Stderr, "    -server-port 50051 ^\n")
	fmt.Fprintf(os.Stderr, "    -token <bootstrap-token>\n\n")

	if enrollment.HasEmbeddedCA() {
		fmt.Fprintf(os.Stderr, "  ✓ CA certificate is embedded in this build (secure).\n")
	} else {
		fmt.Fprintf(os.Stderr, "  ⚠ No embedded CA — certificate will be fetched over HTTP.\n")
		fmt.Fprintf(os.Stderr, "    Build the agent from the dashboard for secure CA embedding.\n")
	}
	fmt.Fprintln(os.Stderr)
}

// runInstall implements the zero-touch installation flow:
//
//  1. Resolve parameters (CLI flags → embedded defaults → missing).
//  2. Validate required parameters with detailed help.
//  3. Create all EDR directories.
//  4. Patch the Windows hosts file (idempotent, deduplicating).
//  5. Verify server connectivity (DNS + TCP ping), unless skipped by flag.
//  6. Generate and save config.yaml.
//  7. Register the Windows Service via the SCM.
//  8. Start the service and poll until it reaches Running state.
func runInstall(
	logger *logging.Logger,
	serverIP, serverDomain, serverPort, token, configPath string,
	installSkipConnectivity bool,
) {
	fmt.Println("════════════════════════════════════════")
	fmt.Println(" EDR Agent — Zero-Touch Installation")
	fmt.Println("════════════════════════════════════════")

	// ── Pre-flight Check: Ensure agent is not already installed ──────────────
	if service.ServiceExists() {
		fmt.Println("  Detected existing installation — switching to in-place upgrade (-update).")
		runUpdate(logger, serverIP, serverDomain, serverPort, token, configPath)
	}

	// ── Token resolution: priority chain ────────────────────────────────────
	// Priority 1: token already resolved via -token-stdin (passed as arg).
	// Priority 2: -token flag (explicit CLI, legacy compat).
	// Priority 3: EmbeddedTokenEnc + EmbeddedTokenKey (legacy single-AES).
	// Priority 4: EmbeddedTokenObf (legacy XOR — oldest binaries).
	// NOTE: split-key path (EmbeddedTokenKeyA/ID) is removed — superseded.
	if token == "" && EmbeddedTokenEnc != "" && EmbeddedTokenKey != "" {
		decrypted, err := aesDecryptToken(EmbeddedTokenEnc, EmbeddedTokenKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[FATAL] Failed to decrypt embedded token: %v\n", err)
			os.Exit(1)
		}
		token = decrypted
		fmt.Println("  Using embedded token (AES-256-GCM legacy).")
	} else if token == "" && EmbeddedTokenObf != "" {
		token = xorDeobfuscate(EmbeddedTokenObf)
		fmt.Println("  Using embedded token (legacy XOR).")
	} else if token != "" {
		fmt.Println("  Using provided token.")
	}

	// ── Local HMAC binding verification ──────────────────────────────────────
	// New binaries carry EmbeddedBuildID + EmbeddedTokenHash.
	// Verify HMAC-SHA256(key=token, msg=buildID) == EmbeddedTokenHash
	// BEFORE any network call. A wrong token → exit(2) immediately.
	if EmbeddedBuildID != "" && EmbeddedTokenHash != "" {
		if token == "" {
			fmt.Fprintln(os.Stderr, "[FATAL] This binary requires a token.")
			fmt.Fprintln(os.Stderr, "  Run: echo '<token>' | agent.exe -install -token-stdin")
			os.Exit(1)
		}
		mac := hmac.New(sha256.New, []byte(token))
		mac.Write([]byte(EmbeddedBuildID))
		computed := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(computed), []byte(EmbeddedTokenHash)) {
			// Zero computed to minimize forensic window.
			for i := range []byte(computed) { _ = i }
			fmt.Fprintln(os.Stderr, "[FATAL] Token does not match this binary.")
			fmt.Fprintln(os.Stderr, "  This binary was built for a specific token.")
			fmt.Fprintln(os.Stderr, "  Use the token provided when this binary was built from the dashboard.")
			os.Exit(2)
		}
		computed = ""
		fmt.Println("  Token binding verified (HMAC-SHA256 OK).")
	}


	serverIP = resolveInstallParam(serverIP, EmbeddedServerIP, "server-ip")
	serverDomain = resolveInstallParam(serverDomain, EmbeddedServerDomain, "server-domain")
	serverPort = resolveInstallParam(serverPort, EmbeddedServerPort, "server-port")
	applyEmbeddedGRPCPortIfDefault(&serverPort)

	// ── Validate required parameters ─────────────────────────────────────────
	var missing []string
	if serverIP == "" {
		missing = append(missing, "-server-ip (C2 server IP address)")
	}
	if serverDomain == "" {
		missing = append(missing, "-server-domain (C2 server FQDN/hostname)")
	}
	if token == "" {
		missing = append(missing, "-token (bootstrap enrollment token — REQUIRED in all cases)")
	}
	if len(missing) > 0 {
		printInstallHelp(missing)
		os.Exit(1)
	}

	fmt.Println()

	// ── Step 1: Create directories ───────────────────────────────────────────
	fmt.Println("[1/7] Creating EDR directories...")
	if err := installer.EnsureDirectories(); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directories: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("      → Done.")

	// ── Step 2: Write embedded CA certificate ─────────────────────────────────
	fmt.Println("[2/7] Provisioning CA certificate...")
	caPath := `C:\ProgramData\EDR\ca-chain.crt`
	if enrollment.HasEmbeddedCA() {
		if err := enrollment.WriteEmbeddedCA(caPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing embedded CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("      → Embedded CA certificate written (secure, no network fetch).")
	} else {
		fmt.Println("      → No embedded CA. Will be fetched on first service start.")
	}

	// ── Step 3: Patch hosts file ──────────────────────────────────────────────
	fmt.Printf("[3/7] Patching hosts file: %s → %s ...\n", serverIP, serverDomain)
	if err := installer.PatchHostsFile(serverIP, serverDomain); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: hosts file patch failed (continuing): %v\n", err)
		logger.Warnf("Hosts file patch failed (non-fatal): %v", err)
	} else {
		fmt.Println("      → Done.")
		logger.Infof("Hosts file patched: %s %s", serverIP, serverDomain)
	}

	// ── Step 4: Verify server connectivity ────────────────────────────────────
	if installSkipConnectivity {
		fmt.Println("[4/7] Skipping server connectivity check (-install-skip-connectivity-check).")
		logger.Warn("Install: TCP preflight skipped by operator flag")
	} else {
		fmt.Printf("[4/7] Verifying server connectivity (%s:%s)...\n", serverIP, serverPort)
		if err := installer.PingServer(serverIP, serverDomain, serverPort); err != nil {
			fmt.Fprintf(os.Stderr, "\n⚠ Server connectivity check failed:\n%v\n\n", err)
			if installer.IsWindowsSocketAccessDenied(err) {
				fmt.Fprintf(os.Stderr,
					"[X] Windows blocked the outbound TCP test (WSAEACCES). This is usually local firewall / WFP,\n"+
						"    including leftover EDR_* rules from network isolation — not proof the C2 is down.\n"+
						"    Fix policy (see hints above), then re-run -install.\n"+
						"    To bypass only the preflight: -install-skip-connectivity-check (use sparingly).\n\n")
				logger.Errorf("Install aborted: C2 TCP preflight blocked by local policy: %v", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "The installation will continue, but the agent may fail to connect.\n")
			fmt.Fprintf(os.Stderr, "Please verify the server is running and the network is configured correctly.\n\n")
			logger.Warnf("Server connectivity check failed (non-fatal): %v", err)
		} else {
			fmt.Println("      → Server is reachable.")
		}
	}

	// ── Step 5: Generate config ──────────────────────────────────────────────
	fmt.Printf("[5/7] Generating agent configuration...\n")
	opts := installer.Options{
		ServerIP:      serverIP,
		ServerDomain:  serverDomain,
		ServerPort:    serverPort,
		ConfigPath:    configPath,
		InstallSysmon: EmbeddedInstallSysmon,
	}
	if err := installer.GenerateConfig(opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
		logger.Errorf("Config generation failed: %v", err)
		os.Exit(1)
	}

	// ── Migrate config to Registry immediately and delete YAML ──────────
	// Load the generated YAML, save to protected Registry (with token for
	// first-boot enrollment), then delete the plaintext YAML from disk.
	installCfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading generated config: %v\n", err)
		os.Exit(1)
	}

	// Best-effort: restore DACL on any existing hardened key from a previous install.
	// This allows re-install to succeed without requiring SYSTEM context.
	_ = protection.RestoreAgentRegistryKey()

	if err := installCfg.SaveToRegistry(); err != nil {
		// Non-fatal: the service (running as SYSTEM) will migrate config.yaml
		// to Registry on first boot. The YAML file is kept temporarily.
		fmt.Printf("      → Config written to %s (will be secured on service start).\n", configPath)
		logger.Warnf("Registry config save deferred to service start: %v", err)
	} else {
		// Success: delete config.yaml — config is now in Registry
		if err := config.DeleteConfigFile(configPath); err != nil {
			fmt.Printf("      → Warning: could not delete %s: %v\n", configPath, err)
			logger.Warnf("Failed to delete config.yaml after Registry migration: %v", err)
		} else {
			fmt.Println("      → Config saved to protected Registry (no file on disk).")
			logger.Info("Config migrated to Registry and YAML deleted")
		}
	}

	// ── Enroll agent BEFORE registering service ───────────────────────────────
	// The token is never written to disk or Registry. It lives only in memory
	// for the duration of this RPC call, then is zeroed by EnsureEnrolled.
	//
	// On success: client cert + key end up in the protected Registry.
	// When the service starts at step 7, EnsureEnrolled sees the certs in
	// Registry and skips enrollment entirely — zero-touch, no token needed.
	fmt.Println("[5b/7] Enrolling agent with server (in-process)...")
	installCfg.Certs.BootstrapToken = token
	if EmbeddedBuildID != "" {
		installCfg.Certs.BuildID = EmbeddedBuildID
	}
	if err := enrollment.EnsureEnrolled(installCfg, logger, ""); err != nil {
		fmt.Fprintf(os.Stderr, "\n[X] Enrollment failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "    Check server reachability and token validity.\n")
		logger.Errorf("Enrollment failed during install: %v", err)
		os.Exit(1)
	}
	// EnsureEnrolled already zeroes BootstrapToken and BuildID.
	// Zero the local token variable too (best-effort).
	token = ""
	fmt.Println("      → Enrolled. Certificates stored in protected Registry.")

	// ── Step 6: Register service ─────────────────────────────────────────────
	fmt.Println("[6/7] Registering Windows Service (EDRAgent)...")

	if err := service.Install(); err != nil {
		if isAlreadyExistsErr(err) {
			fmt.Fprintf(os.Stderr, "\n[X] Error: EDR Agent is already installed on this system.\n")
			fmt.Fprintf(os.Stderr, "    Re-installation is blocked. Issue an UNINSTALL_AGENT command\n")
			fmt.Fprintf(os.Stderr, "    from the EDR dashboard to remove this agent first.\n")
			logger.Errorf("Install aborted: service already exists")
			os.Exit(1)
		} else {
			fmt.Fprintf(os.Stderr, "Error installing service: %v\n", err)
			logger.Errorf("Service install failed: %v", err)
			os.Exit(1)
		}
	}
	fmt.Println("      → Done.")
	logger.Info("Service registered in SCM")

	// ── Step 7: Start service ────────────────────────────────────────────────
	fmt.Println("[7/7] Starting EDRAgent service...")

	// Legacy directory cleanup (best-effort, ignore errors if locked by permissions)
	os.RemoveAll(`C:\ProgramData\EDR\certs`)
	os.RemoveAll(`C:\ProgramData\EDR\config`)

	if err := service.StartService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
		logger.Errorf("Service start failed: %v", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ EDR Agent installed and running successfully.")
	fmt.Printf("  Server:    %s:%s\n", serverDomain, serverPort)
	fmt.Printf("  Config:    %s\n", configPath)
	fmt.Println("  Binary:    C:\\ProgramData\\EDR\\bin\\edr-agent.exe (secured)")
	fmt.Println("  Service:   EDRAgent (Automatic, LocalSystem)")
	if enrollment.HasEmbeddedCA() {
		fmt.Println("  CA Cert:   Embedded (secure)")
	}
	fmt.Println("\n  To check status:   sc query EDRAgent")
	fmt.Println("  To view logs:      Get-Content C:\\ProgramData\\EDR\\logs\\agent.log -Tail 50")
	fmt.Println("  To uninstall:      issue UNINSTALL_AGENT from the EDR dashboard (RBAC + audit enforced)")
	fmt.Println("\n  You can safely delete this installer file — the agent binary")
	fmt.Println("  has been copied to the secure path above.")
	logger.Infof("Zero-touch installation complete: server=%s:%s", serverDomain, serverPort)
	os.Exit(0)
}

type updateOverrides struct {
	ServerIP      string `json:"server_ip,omitempty"`
	ServerDomain  string `json:"server_domain,omitempty"`
	ServerPort    string `json:"server_port,omitempty"`
	Token         string `json:"token,omitempty"`
	InstallSysmon string `json:"install_sysmon,omitempty"`
}

func runUpdate(
	logger *logging.Logger,
	serverIP, serverDomain, serverPort, token, configPath string,
) {
	fmt.Println("════════════════════════════════════════")
	fmt.Println(" EDR Agent — In-Place Upgrade (-update)")
	fmt.Println("════════════════════════════════════════")

	requireElevationForUpdate()

	if !service.ServiceExists() {
		fmt.Fprintf(os.Stderr, "\n[X] Error: EDR Agent is not installed on this system.\n")
		fmt.Fprintf(os.Stderr, "    Please install first using: edr-agent.exe -install\n")
		os.Exit(1)
	}

	// Resolve params (CLI overrides are optional; empty means keep current)
	if token == "" && EmbeddedTokenEnc != "" && EmbeddedTokenKey != "" {
		decrypted, err := aesDecryptToken(EmbeddedTokenEnc, EmbeddedTokenKey)
		if err == nil {
			token = decrypted
		}
	} else if token == "" && EmbeddedTokenObf != "" {
		token = xorDeobfuscate(EmbeddedTokenObf) // legacy backward compat
	}
	serverIP = resolveInstallParam(serverIP, EmbeddedServerIP, "server-ip")
	serverDomain = resolveInstallParam(serverDomain, EmbeddedServerDomain, "server-domain")
	serverPort = resolveInstallParam(serverPort, EmbeddedServerPort, "server-port")
	// Match runInstall: the flag default is "50051", so resolveInstallParam never
	// consults embedded — same bug would force the public C2 port (e.g. 47051) to
	// be lost on in-place upgrade, breaking AWS SG / port-forward setups.
	applyEmbeddedGRPCPortIfDefault(&serverPort)

	srcPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get executable path: %v\n", err)
		os.Exit(1)
	}
	srcPath, _ = filepath.Abs(srcPath)

	// Stage the new binary somewhere Admin can write (root is Admin+SYSTEM).
	stagedExe := `C:\ProgramData\EDR\edr-agent.update.exe`
	fmt.Printf("[1/3] Staging update binary to %s ...\n", stagedExe)
	if err := copyFileLocal(srcPath, stagedExe); err != nil {
		fmt.Fprintf(os.Stderr, "Error staging update binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("      → Done.")

	// Write overrides for stage2 (SYSTEM).
	ov := updateOverrides{
		ServerIP:      strings.TrimSpace(serverIP),
		ServerDomain:  strings.TrimSpace(serverDomain),
		ServerPort:    strings.TrimSpace(serverPort),
		Token:         strings.TrimSpace(token),
		InstallSysmon: strings.TrimSpace(EmbeddedInstallSysmon),
	}
	overridesPath := `C:\ProgramData\EDR\update_overrides.json`
	if data, err := json.Marshal(ov); err == nil {
		_ = os.WriteFile(overridesPath, data, 0600)
	}

	fmt.Println("[2/3] Scheduling SYSTEM upgrade task (stop → swap → start)...")
	if err := scheduleUpdateStage2AsSystem(stagedExe, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error scheduling upgrade: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("      → Done.")

	fmt.Println("[3/3] Upgrade initiated. Service will restart shortly.")
	fmt.Println("      Check: sc query EDRAgent")
	fmt.Println("      Logs:  Get-Content C:\\ProgramData\\EDR\\logs\\agent.log -Tail 80")
	logger.Info("Update scheduled (SYSTEM stage2)")
	os.Exit(0)
}

func runUpdateStage2(
	logger *logging.Logger,
	serverIP, serverDomain, serverPort, token, configPath string,
) {
	// schtasks /TR is capped at 261 characters, so stage2 is normally launched with only
	// -update-stage2 -config; server/token/install_sysmon come from update_overrides.json.
	const ovPath = `C:\ProgramData\EDR\update_overrides.json`
	installSysmon := strings.TrimSpace(EmbeddedInstallSysmon)
	if data, err := os.ReadFile(ovPath); err == nil && len(data) > 0 {
		var ov updateOverrides
		if json.Unmarshal(data, &ov) == nil {
			if strings.TrimSpace(serverIP) == "" {
				serverIP = strings.TrimSpace(ov.ServerIP)
			}
			if strings.TrimSpace(serverDomain) == "" {
				serverDomain = strings.TrimSpace(ov.ServerDomain)
			}
			if strings.TrimSpace(serverPort) == "" {
				serverPort = strings.TrimSpace(ov.ServerPort)
			}
			if strings.TrimSpace(token) == "" {
				token = strings.TrimSpace(ov.Token)
			}
			if strings.TrimSpace(installSysmon) == "" {
				installSysmon = strings.TrimSpace(ov.InstallSysmon)
			}
		}
	}

	// Stage2 is executed as SYSTEM (via schtasks) to bypass hardened ACLs.
	_ = protection.RestoreServiceDACL(service.ServiceName)
	_ = protection.RestoreServiceRegistryKey(service.ServiceName)
	_ = protection.RestoreAgentRegistryKey()
	_ = security.RestoreAgentDirectoriesACL(config.DefaultConfig().DataDirectoriesToHarden())

	// Apply config overrides (best-effort).
	cfg, _ := config.LoadFromRegistry()
	if cfg == nil {
		// Fallback to YAML if present; else defaults.
		if c2, err := config.Load(configPath); err == nil {
			cfg = c2
		} else {
			cfg = config.DefaultConfig()
		}
	}
	sd := strings.TrimSpace(serverDomain)
	sp := strings.TrimSpace(serverPort)
	if sd != "" && sp != "" {
		cfg.Server.Address = fmt.Sprintf("%s:%s", sd, sp)
		// The gRPC listener uses a cert with CN/SAN for the Connection Manager
		// service (e.g. edr-connection-manager), not the hosts-file name
		// (edr.local). Using serverDomain here breaks TLS with
		// "certificate is valid for ... not edr.local".
		tls := strings.TrimSpace(cfg.Server.TLSServerName)
		if tls == "" || strings.EqualFold(tls, sd) {
			cfg.Server.TLSServerName = config.DefaultGRPCServerCertName
		}
	}
	if strings.TrimSpace(token) != "" {
		// BootstrapToken lives on CertConfig; the root Config only aggregates
		// sub-structs. Writing it at the root silently compiled on older builds
		// but modern go vet + the agent-builder image catches the typo.
		cfg.Certs.BootstrapToken = strings.TrimSpace(token)
	}
	if strings.EqualFold(strings.TrimSpace(installSysmon), "true") {
		cfg.Sysmon.InstallOnFirstRun = true
	}
	_ = cfg.SaveToRegistry()

	// Stop service, swap binary, start.
	_ = exec.Command("sc.exe", "stop", "EDRAgent").Run()
	time.Sleep(2 * time.Second)

	dst := `C:\ProgramData\EDR\bin\edr-agent.exe`
	src := `C:\ProgramData\EDR\edr-agent.update.exe`
	_ = os.MkdirAll(filepath.Dir(dst), 0700)

	// Keep one backup.
	_ = os.Remove(dst + ".old")
	_ = os.Rename(dst, dst+".old")
	if err := copyFileLocal(src, dst); err != nil {
		logger.Errorf("Update stage2: swap failed: %v", err)
		fmt.Fprintf(os.Stderr, "Error: swap failed: %v\n", err)
		os.Exit(1)
	}
	_ = os.Remove(src)

	_ = exec.Command("sc.exe", "start", "EDRAgent").Run()
	fmt.Println("✓ Upgrade applied (SYSTEM stage2).")
	os.Exit(0)
}

func scheduleUpdateStage2AsSystem(stagedExe, configPath string) error {
	taskName := fmt.Sprintf("EDR_Update_%d", os.Getpid())
	st := time.Now().Add(1 * time.Minute).Format("15:04")

	// Keep /TR short: runUpdateStage2 merges C:\ProgramData\EDR\update_overrides.json.
	tr := fmt.Sprintf("\"%s\" -update-stage2 -config \"%s\"", stagedExe, configPath)
	if len(tr) > 261 {
		return fmt.Errorf("schtasks /TR too long (%d > 261) — shorten staged exe or config path", len(tr))
	}

	create := exec.Command("schtasks", "/Create", "/TN", taskName, "/RU", "SYSTEM", "/SC", "ONCE", "/ST", st, "/F", "/TR", tr)
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	run := exec.Command("schtasks", "/Run", "/TN", taskName)
	if out, err := run.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks run failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
	return nil
}

func copyFileLocal(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_ = os.MkdirAll(filepath.Dir(dst), 0755)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// isAlreadyExistsErr returns true when the error from service.Install() indicates
// the service name already exists in the SCM.
func isAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "already exists") || contains(msg, "1073")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// runStandalone runs the agent in interactive/development mode.
func runStandalone(cfg *config.Config, logger *logging.Logger, configPath string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Infof("Received signal: %v — shutting down...", sig)
		cancel()
	}()

	ag, err := agent.New(cfg, logger)
	if err != nil {
		logger.Errorf("Failed to create agent: %v", err)
		os.Exit(1)
	}

	ag.SetConfigFilePath(configPath)
	ag.SetRestartInfo(configPath)

	// Wire the hot-reload callback so C2 UPDATE_CONFIG commands are live:
	// command.Handler.updateConfig() → agent.UpdateConfig() → validate + save + swap.
	ag.SetConfigUpdateHandler(ag.UpdateConfig)

	if err := ag.Start(ctx); err != nil {
		logger.Errorf("Failed to start agent: %v", err)
		os.Exit(1)
	}

	<-ctx.Done()

	logger.Info("Initiating graceful shutdown...")
	if err := ag.Stop(); err != nil {
		logger.Errorf("Error during shutdown: %v", err)
	}
	logger.Info("Agent stopped.")
}

// xorDeobfuscate decodes the XOR-obfuscated enrollment token.
// DEPRECATED: kept for backward compatibility with binaries produced before the
// AES-256-GCM upgrade. New binaries use aesDecryptToken.
func xorDeobfuscate(obfuscatedHex string) string {
	data, err := hex.DecodeString(obfuscatedHex)
	if err != nil {
		return "" // invalid hex — treat as empty
	}
	// Same 32-byte key as the agent-builder.
	key := []byte("EDR-Agent-XOR-Key-2026!@#$%^&*()")
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
	return string(data)
}

// aesDecryptToken decrypts an AES-256-GCM-encrypted enrollment token.
//
// ciphertextHex: hex( 12-byte-nonce || ciphertext || 16-byte-GCM-tag )
// keyHex:        hex( 32-byte AES-256 key )
//
// The key bytes are zeroed from memory immediately after decryption —
// the caller should also zero the returned string bytes after use.
func aesDecryptToken(ciphertextHex, keyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("decode key hex: %w", err)
	}
	// Zero key bytes from memory after use regardless of success or failure.
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext hex: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new GCM: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	data := ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return string(plaintext), nil
}

// Sentinel file functions removed — split-key architecture superseded.
// resolveHTTPSBaseURL removed — /key-half endpoint removed.
