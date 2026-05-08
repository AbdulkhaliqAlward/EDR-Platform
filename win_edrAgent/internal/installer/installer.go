// Package installer provides the Zero-Touch / CLI-Driven installation logic for the EDR Agent.
// It handles hosts-file DNS injection, dynamic config generation, and Windows Service registration.
//
// This package is Windows-only and must be run with elevated (Administrator/SYSTEM) privileges.
//
//go:build windows
// +build windows

package installer

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/security"
)

const (
	// hostsFile is the canonical Windows hosts file path.
	hostsFile = `C:\Windows\System32\drivers\etc\hosts`

	// ConfigDir is the protected directory for agent configuration.
	ConfigDir = `C:\ProgramData\EDR`

	// DefaultConfigPath is the standard config file path.
	DefaultConfigPath = `C:\ProgramData\EDR\config.yaml`

	// ServiceName matches the name registered in the SCM.
	ServiceName = "EDRAgent"

	// hostsComment is the marker appended to EDR-managed hosts entries.
	hostsComment = "# EDR C2"
)

// Options carries the parameters supplied via CLI flags during installation.
type Options struct {
	// ServerIP is the raw IP of the C2 server to inject into the hosts file.
	ServerIP string

	// ServerDomain is the FQDN/hostname the agent will use to connect to C2.
	// This is also the domain injected into the hosts file.
	ServerDomain string

	// ServerPort is the gRPC port (default "50051").
	ServerPort string

	// Token field removed: enrollment token is no longer written to disk or
	// Registry under any circumstances. It is passed via stdin at install time,
	// used in-memory for the RegisterAgent gRPC call, then immediately zeroed.
	// See: win_edrAgent/cmd/agent/main.go runInstall()

	// ConfigPath is the absolute path where config.yaml will be written.
	// Defaults to DefaultConfigPath.
	ConfigPath string

	// InstallSysmon is "true" to enable sysmon.install_on_first_run in generated config.
	InstallSysmon string
}

// effectiveConfigPath returns opts.ConfigPath if set, otherwise DefaultConfigPath.
func (o *Options) effectiveConfigPath() string {
	if o.ConfigPath != "" {
		return o.ConfigPath
	}
	return DefaultConfigPath
}

// =============================================================================
// PatchHostsFile
// =============================================================================

// PatchHostsFile ensures that the Windows hosts file contains exactly ONE mapping
// of serverIP → serverDomain with the EDR C2 comment marker.
//
// Unlike the previous implementation that only appended, this version:
//  1. Removes ALL existing lines with the "# EDR C2" marker
//  2. Removes any line mapping a different IP to the same domain
//  3. Then appends the single correct entry
//
// This prevents duplicate/stale entries from accumulating across reinstalls.
//
// Requires Administrator or SYSTEM privileges on the calling process.
func PatchHostsFile(serverIP, serverDomain string) error {
	if serverIP == "" || serverDomain == "" {
		return fmt.Errorf("PatchHostsFile: serverIP and serverDomain must not be empty")
	}

	// ── Read existing content ──────────────────────────────────────────────────
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// ── Filter out stale EDR entries, check if correct entry already exists ───
	var cleanLines []string
	alreadyCorrect := false

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		stripped := strings.TrimSpace(line)

		// Remove any line with the EDR C2 comment marker (our previous entries)
		if strings.Contains(line, hostsComment) {
			// Check if this is already the exact correct entry
			fields := strings.Fields(stripped)
			if len(fields) >= 2 && fields[0] == serverIP &&
				strings.EqualFold(fields[1], serverDomain) {
				alreadyCorrect = true
				cleanLines = append(cleanLines, line) // keep the correct one
			}
			// else: stale entry — drop it
			continue
		}

		// Also remove any uncommented line mapping ANY IP to our domain
		// (prevents conflicts from manual edits)
		if stripped != "" && !strings.HasPrefix(stripped, "#") {
			fields := strings.Fields(stripped)
			if len(fields) >= 2 {
				domainMatch := false
				for _, f := range fields[1:] {
					if strings.EqualFold(f, serverDomain) {
						domainMatch = true
						break
					}
				}
				if domainMatch && fields[0] != serverIP {
					// Different IP → stale, remove it
					continue
				}
			}
		}

		cleanLines = append(cleanLines, line)
	}

	// ── If correct entry already exists, write cleaned content and return ─────
	if alreadyCorrect {
		cleaned := strings.Join(cleanLines, "\n")
		if !strings.HasSuffix(cleaned, "\n") {
			cleaned += "\n"
		}
		return os.WriteFile(hostsFile, []byte(cleaned), 0644)
	}

	// ── Append the correct EDR entry ─────────────────────────────────────────
	cleaned := strings.Join(cleanLines, "\n")
	if len(cleaned) > 0 && cleaned[len(cleaned)-1] != '\n' {
		cleaned += "\n"
	}
	entry := fmt.Sprintf("%s\t%s\t%s\n", serverIP, serverDomain, hostsComment)
	cleaned += entry

	if err := os.WriteFile(hostsFile, []byte(cleaned), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	return nil
}

// =============================================================================
// GenerateConfig
// =============================================================================

// GenerateConfig builds a complete agent Config from sensible defaults, overrides
// the dynamic fields (Server.Address, Certs.BootstrapToken, Agent.ID), and saves
// it to opts.ConfigPath (or DefaultConfigPath).
//
// The generated config.yaml is the canonical source of truth used by the agent
// when started by the SCM.
func GenerateConfig(opts Options) error {
	if opts.ServerDomain == "" {
		return fmt.Errorf("GenerateConfig: ServerDomain must not be empty")
	}
	if opts.ServerPort == "" {
		opts.ServerPort = "50051"
	}

	// ── Build configuration from proven defaults ───────────────────────────────
	cfg := config.DefaultConfig()

	// Override the dynamic fields.
	cfg.Server.Address = opts.ServerDomain + ":" + opts.ServerPort
	// NOTE: cfg.Certs.BootstrapToken is intentionally NOT set here.
	// The token is passed via stdin and kept in-memory only. It is never
	// written to config.yaml or the Registry. See main.go runInstall().
	cfg.Agent.ID = uuid.New().String()

	// Optional: Sysmon bootstrap (dashboard build flag).
	// This is safe even when Sysmon is not present; the agent will no-op unless enabled.
	if strings.EqualFold(opts.InstallSysmon, "true") {
		cfg.Sysmon.InstallOnFirstRun = true
	}

	// ── Create the target directory ────────────────────────────────────────────
	cfgPath := opts.effectiveConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// ── Persist to disk ────────────────────────────────────────────────────────
	if err := cfg.Save(cfgPath); err != nil {
		return fmt.Errorf("failed to save generated config: %w", err)
	}

	return nil
}

// =============================================================================
// InstallAndStart
// =============================================================================

// InstallAndStart registers the agent as a Windows Service and starts it.
// If the service already exists (e.g., a previous install), it is first
// uninstalled so the registration is always fresh.
//
// The SCM is connected twice intentionally: once via service.Install() to create
// the service entry, and once here to call Start() — this avoids exposing a raw
// mgr.Service handle through the service package API.
func InstallAndStart(exePath string) error {
	// ── Connect to SCM ─────────────────────────────────────────────────────────
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// ── Open service handle ────────────────────────────────────────────────────
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found in SCM (was Install() called?): %w", ServiceName, err)
	}
	defer s.Close()

	// ── Start the service ──────────────────────────────────────────────────────
	if err := s.Start(); err != nil {
		// "already running" is not an error for idempotency.
		if !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("failed to start service: %w", err)
		}
	}

	// ── Poll until Running (up to 10 s) ───────────────────────────────────────
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service status: %w", err)
		}
		if status.State == svc.Running {
			return nil
		}
		if status.State == svc.Stopped {
			// Provide actionable diagnostics while the installer still has access.
			const logPath = `C:\ProgramData\EDR\logs\agent.log`
			if tail, tErr := tailFileLines(logPath, 60); tErr == nil && strings.TrimSpace(tail) != "" {
				return fmt.Errorf("service stopped unexpectedly during startup; recent agent log:\n%s", tail)
			}
			return fmt.Errorf("service stopped unexpectedly during startup — check %s for details", logPath)
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("service did not reach Running state within 10s")
}

func tailFileLines(path string, n int) (string, error) {
	if n <= 0 {
		n = 50
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(s, "\n")
	// Drop trailing empty line from final newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) <= n {
		return strings.Join(lines, "\n"), nil
	}
	return strings.Join(lines[len(lines)-n:], "\n"), nil
}

// =============================================================================
// EnsureDirectories
// =============================================================================

// EnsureDirectories creates all required EDR directories with appropriate
// permissions. This is called once during installation.
func EnsureDirectories() error {
	dirs := []string{
		`C:\ProgramData\EDR`,
		`C:\ProgramData\EDR\logs`,
		`C:\ProgramData\EDR\queue`,
		`C:\ProgramData\EDR\quarantine`,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	// Root directory stays writable by elevated Administrators so the SYSTEM
	// scheduled task spawned by an authorised UNINSTALL_AGENT command can
	// finish removing logs/queue/quarantine after the service exits.
	_ = security.ApplyRestrictedDACL(`C:\ProgramData\EDR`)
	return nil
}

// wsaeacces is Windows WSAEACCES (10013): "An attempt was made to access a socket
// in a way forbidden by its access permissions." Usually local WFP/firewall policy
// (including leftover EDR network-isolation rules), not a down C2 server.
const wsaeacces = syscall.Errno(10013)

// IsWindowsSocketAccessDenied reports whether err is (or wraps) WSAEACCES / the
// common English WinSock message for local policy blocking the connect().
func IsWindowsSocketAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		var op *net.OpError
		if errors.As(e, &op) && op.Err != nil {
			if errno, ok := op.Err.(syscall.Errno); ok && errno == wsaeacces {
				return true
			}
		}
		if strings.Contains(strings.ToLower(e.Error()), "forbidden by its access permissions") {
			return true
		}
	}
	return false
}

func windowsSocketAccessDeniedHints(c2Addr string) string {
	return strings.TrimSpace(`
This error almost always means Windows Firewall / WFP (or leftover EDR isolation rules)
is blocking outbound TCP from this process — not that the C2 port is closed.

Try (elevated PowerShell or CMD), then re-run -install:

  netsh advfirewall firewall delete rule name=EDR_C2_GRPC_OUT
  netsh advfirewall firewall delete rule name=EDR_C2_GRPC_IN
  netsh advfirewall firewall delete rule name=EDR_C2_HTTP_OUT
  netsh advfirewall firewall delete rule name=EDR_C2_HTTP_IN
  netsh advfirewall firewall delete rule name=EDR_C2_ALLOW_OUT
  netsh advfirewall firewall delete rule name=EDR_C2_ALLOW_IN
  netsh advfirewall firewall delete rule name=EDR_DNS_ALLOW
  netsh advfirewall firewall delete rule name=EDR_LOOPBACK_ALLOW
  netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

Optional diagnostics:
  netsh advfirewall firewall show rule name=all | findstr /I EDR_
  netsh interface ipv4 show excludedportrange protocol=tcp

If the C2 is intentionally unreachable until later, you may use:
  -install-skip-connectivity-check   (not recommended until policy is understood)
`) + "\n\nTarget: " + c2Addr
}

// =============================================================================
// PingServer
// =============================================================================

// PingServer performs pre-installation connectivity checks:
//  1. DNS resolution of serverDomain → verify it resolves to an IP address.
//  2. TCP connectivity to serverIP:serverPort → verify the C2 server is reachable.
//
// Returns a descriptive error if either check fails, helping the installer
// diagnose network issues before the agent service starts.
func PingServer(serverIP, serverDomain, serverPort string) error {
	// ── DNS resolution check ───────────────────────────────────────────────────
	if serverDomain != "" {
		addrs, err := net.LookupHost(serverDomain)
		if err != nil {
			return fmt.Errorf(
				"DNS resolution failed for %q: %w\n"+
					"  Possible causes:\n"+
					"  - The hosts file was not patched correctly\n"+
					"  - DNS server does not have a record for this domain\n"+
					"  - Network is not connected",
				serverDomain, err,
			)
		}
		// Verify the resolved IP matches the expected server IP
		if serverIP != "" {
			found := false
			for _, addr := range addrs {
				if addr == serverIP {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf(
					"DNS resolution mismatch: %q resolved to %v, expected %s\n"+
						"  Check the hosts file or DNS configuration",
					serverDomain, addrs, serverIP,
				)
			}
		}
	}

	// ── TCP connectivity check ─────────────────────────────────────────────────
	target := serverIP
	if target == "" {
		target = serverDomain
	}
	if target == "" || serverPort == "" {
		return fmt.Errorf("cannot ping server: IP/domain and port are required")
	}

	addr := net.JoinHostPort(target, serverPort)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		msg := fmt.Sprintf(
			"TCP connection to %s failed: %v\n"+
				"  Possible causes:\n"+
				"  - The C2 server is not running or not listening on port %s\n"+
				"  - A firewall is blocking the connection\n"+
				"  - The server IP address is incorrect",
			addr, err, serverPort,
		)
		if IsWindowsSocketAccessDenied(err) {
			return errors.New(msg + "\n\n" + windowsSocketAccessDeniedHints(addr))
		}
		return errors.New(msg)
	}
	conn.Close()

	return nil
}

