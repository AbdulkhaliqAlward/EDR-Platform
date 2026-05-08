// Package enrollment provides agent self-enrollment with the Connection Manager.
package enrollment

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/edr-platform/win-agent/internal/config"
	grpcclient "github.com/edr-platform/win-agent/internal/grpc"
	"github.com/edr-platform/win-agent/internal/logging"
	pb "github.com/edr-platform/win-agent/internal/pb"
)

const (
	// dialTimeout caps the TCP+TLS connection establishment phase.
	// If the server does not complete the TLS handshake within this window,
	// the dial fails with a clear connectivity error instead of silently
	// consuming the entire registerTimeout and returning DeadlineExceeded.
	dialTimeout = 15 * time.Second

	// registerTimeout caps the RegisterAgent RPC itself, measured from the
	// moment the gRPC connection is READY. Kept generous to accommodate
	// first-enrollment DB operations (token validation, cert issuance, etc.).
	registerTimeout = 60 * time.Second
)

// ErrBootstrapTokenRequired is returned when first-time enrollment needs a token but none is configured.
var ErrBootstrapTokenRequired = errors.New("bootstrap token is required for enrollment")

// IsFatalEnrollmentError reports errors that retrying will not fix (bad token, rejected, bad CSR, missing CA PEM).
func IsFatalEnrollmentError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBootstrapTokenRequired) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "enrollment rejected:") ||
		strings.Contains(s, "generate CSR:") ||
		strings.Contains(s, "failed to parse CA certificate") ||
		strings.Contains(s, "server approved but did not return certificate") ||
		strings.Contains(s, "save certificate:")
}

// EnsureEnrolled ensures the agent has a valid client certificate. If cert and key
// already exist at the configured paths, it returns nil. Otherwise it performs
// registration with the Connection Manager using the bootstrap token and CSR,
// then saves the issued certificate and updates the config with the assigned agent ID.
// If configFilePath is non-empty and a new AgentID was received, the config is persisted to that file.
func EnsureEnrolled(cfg *config.Config, logger *logging.Logger, configFilePath string) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	if logger == nil {
		return errors.New("logger is required")
	}

	// Already enrolled if certificates live in Registry (zero-disk mode).
	if len(cfg.Certs.CertPEM) > 0 && len(cfg.Certs.KeyPEM) > 0 {
		if certID := extractCertCNFromPEM(cfg.Certs.CertPEM); certID != "" && certID != cfg.Agent.ID {
			logger.Infof("Syncing Agent.ID from certificate CN: %s → %s", cfg.Agent.ID, certID)
			cfg.Agent.ID = certID
			if configFilePath != "" {
				if err := cfg.SaveToRegistry(); err != nil {
					logger.Warnf("Failed to save config to Registry after CN sync: %v", err)
				}
			}
		}
		logger.Info("Agent already enrolled (certificates in Registry)")
		return nil
	}

	// Already enrolled if both cert and key exist on disk
	if _, err := os.Stat(cfg.Certs.CertPath); err == nil {
		if _, err := os.Stat(cfg.Certs.KeyPath); err == nil {
			// Sync cfg.Agent.ID from the certificate CN.
			// After re-installation, config.yaml may have a NEWLY generated UUID
			// while the existing certificate still carries the SERVER-ASSIGNED UUID
			// in its CN. Without this sync, the Heartbeat sends the wrong agent_id.
			if certID := extractCertCN(cfg.Certs.CertPath, logger); certID != "" && certID != cfg.Agent.ID {
				logger.Infof("Syncing Agent.ID from certificate CN: %s → %s", cfg.Agent.ID, certID)
				cfg.Agent.ID = certID
				if configFilePath != "" {
					if err := cfg.SaveToRegistry(); err != nil {
						logger.Warnf("Failed to save config to Registry after CN sync: %v", err)
					}
				}
			}
			logger.Info("Agent already enrolled")
			return nil
		}
	}

	cm := grpcclient.NewCertManagerFromConfig(cfg, logger)

	if cfg.Certs.BootstrapToken == "" {
		return fmt.Errorf("%w; set certs.bootstrap_token in config", ErrBootstrapTokenRequired)
	}
	logger.Infof("Enrollment bootstrap token ready: len=%d", len(strings.TrimSpace(cfg.Certs.BootstrapToken)))

	csrPEM, err := cm.GenerateCSR(cfg.Agent.ID, cfg.Agent.Hostname)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	// Dial the Connection Manager for enrollment.
	// Use TLS with CA cert only (no client cert — we're trying to obtain one).
	// The server's tls.Config uses VerifyClientCertIfGiven, so this works.
	var dialOpt grpc.DialOption
	if cfg.Server.Insecure {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
		logger.Warn("Enrollment using PLAINTEXT gRPC (insecure mode)")
	} else {
		var caCert []byte
		if b, err := os.ReadFile(cfg.Certs.CAPath); err == nil {
			caCert = b
		} else if len(cfg.Certs.CACertPEM) > 0 {
			caCert = cfg.Certs.CACertPEM
			logger.Info("Enrollment TLS: using CA certificate from Registry (embedded CA)")
		} else {
			return fmt.Errorf("read CA certificate for enrollment TLS: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate for enrollment TLS")
		}
		tlsCfg := &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		}
		// ServerName override: allows the agent to connect to a custom deployment
		// domain (e.g. "edr.local" or a bare IP) while validating the server cert
		// against the internal service name the cert was actually issued for
		// (e.g. "edr-connection-manager"). This resolves x509 SAN mismatches
		// without requiring re-issuance of server certificates.
		if cfg.Server.TLSServerName != "" {
			tlsCfg.ServerName = cfg.Server.TLSServerName
			logger.Infof("Enrollment TLS: ServerName override → %q (connecting to %s)",
				cfg.Server.TLSServerName, cfg.Server.Address)
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
		logger.Info("Enrollment using TLS (server-auth only, no client cert)")
	}

	// Establish TCP+TLS with an explicit deadline so a hung TLS handshake
	// (server accepted TCP but not responding to ClientHello) fails fast
	// with a clear error rather than waiting for the full registerTimeout.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dialCancel()
	//nolint:staticcheck // grpc.DialContext is deprecated in favour of grpc.NewClient,
	// but grpc.NewClient has no WithBlock() equivalent; retained intentionally.
	conn, err := grpc.DialContext(dialCtx, cfg.Server.Address, dialOpt, grpc.WithBlock()) //nolint:staticcheck
	if err != nil {
		if dialCtx.Err() != nil {
			return fmt.Errorf("dial server: connection to %s timed out after %s — server may be unreachable or TLS handshake failed: %w", cfg.Server.Address, dialTimeout, err)
		}
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.Close()
	logger.Infof("Enrollment: gRPC connection established to %s (TLS ok)", cfg.Server.Address)

	client := pb.NewEventIngestionServiceClient(conn)
	hardwareID, src, err := GetHardwareIDWithSource()
	if err != nil {
		logger.Warnf("HardwareID unavailable; enrollment may be rejected: %v", err)
	}
	hardwareID = strings.TrimSpace(hardwareID)
	if hardwareID == "" {
		return fmt.Errorf("hardware_id is required for enrollment (could not determine a stable device id)")
	}
	logger.Infof("Enrollment hardware_id ready: source=%s len=%d", src, len(hardwareID))
	// NOTE: Our protobuf files were manually patched in some environments where
	// protoc is unavailable. To guarantee the server receives the hardware_id
	// even if the generated descriptor is stale, also send it via Tags (which is
	// always present in the original schema).
	// Build machine fingerprint for forensic audit trail.
	// SHA-256(hostname + first_mac_address + os_version) is stable per machine.
	// Sent in the Tags map so no proto change is required.
	// The server logs this in the enrollment audit event.
	machineFingerprint := computeMachineFingerprint(cfg.Agent.Hostname)

	tags := map[string]string{
		"hardware_id":         hardwareID,
		"machine_fingerprint": machineFingerprint,
	}
	// Include build_id tag if set (new architecture).
	// agent_service.go uses this for the BuildID-path lookup: GetByBuildID()
	// then verifies the token hash matches before granting enrollment.
	// Zero BuildID from cfg after copying to tags so it doesn't linger in memory.
	if cfg.Certs.BuildID != "" {
		tags["build_id"] = cfg.Certs.BuildID
		cfg.Certs.BuildID = ""
	}

	req := &pb.AgentRegistrationRequest{
		InstallationToken: cfg.Certs.BootstrapToken,
		AgentId:           cfg.Agent.ID,
		Csr:               csrPEM,
		Hostname:          cfg.Agent.Hostname,
		OsType:            "windows",
		HardwareId:        hardwareID,
		Tags:              tags,
	}

	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()

	resp, err := client.RegisterAgent(ctx, req)
	if err != nil {
		return fmt.Errorf("register agent: %w", err)
	}

	if resp.GetStatus() != pb.RegistrationStatus_REGISTRATION_STATUS_APPROVED {
		msg := resp.GetMessage()
		if msg == "" {
			msg = "registration not approved"
		}
		return fmt.Errorf("enrollment rejected: %s", msg) // fatal — IsFatalEnrollmentError matches substring
	}

	cert := resp.GetCertificate()
	caChain := resp.GetCaChain()
	if len(cert) == 0 || len(caChain) == 0 {
		return errors.New("server approved but did not return certificate or CA chain")
	}

	if err := cm.SaveCertificate(cert, caChain); err != nil {
		return fmt.Errorf("save certificate: %w", err)
	}

	cfg.Agent.ID = resp.GetAgentId()
	logger.Infof("Enrollment successful; agent ID: %s", cfg.Agent.ID)

	// SECURITY: Wipe the bootstrap token from config IMMEDIATELY after
	// successful enrollment. The token is a one-time secret used only for
	// the initial RegisterAgent RPC. Leaving it on disk would allow anyone
	// with file access to read the plaintext token and use it to:
	//   - Register rogue agents
	//   - Uninstall the agent (same token)
	// After this point, the agent authenticates via mTLS certificate only.
	cfg.Certs.BootstrapToken = ""
	logger.Info("Bootstrap token wiped from config (one-time use)")

	// ── Migrate certificate files to Registry (zero disk footprint) ──────
	// Read cert/key/CA PEM data from disk files into config struct,
	// then delete the files. The PEM data lives in the protected Registry.
	if certPEM, err := os.ReadFile(cfg.Certs.CertPath); err == nil {
		cfg.Certs.CertPEM = certPEM
	}
	if keyPEM, err := os.ReadFile(cfg.Certs.KeyPath); err == nil {
		cfg.Certs.KeyPEM = keyPEM
	}
	if caPEM, err := os.ReadFile(cfg.Certs.CAPath); err == nil {
		cfg.Certs.CACertPEM = caPEM
	}

	// Save updated config (with inline PEM data) to Registry
	if err := cfg.SaveToRegistry(); err != nil {
		logger.Warnf("Failed to save post-enrollment config to Registry: %v", err)
	} else {
		logger.Info("Post-enrollment config + certificates saved to protected Registry")
		// Delete cert files from disk — they now live in Registry
		_ = os.Remove(cfg.Certs.CertPath)
		_ = os.Remove(cfg.Certs.KeyPath)
		_ = os.Remove(cfg.Certs.CAPath)
		logger.Info("Certificate files deleted from disk (migrated to Registry)")
	}

	return nil
}

// extractCertCN reads a PEM certificate file and returns its Subject.CommonName.
// Returns "" on any error (missing file, bad PEM, etc.) — caller handles fallback.
func extractCertCN(certPath string, logger *logging.Logger) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	return extractCertCNFromPEM(data)
}

func extractCertCNFromPEM(pemData []byte) string {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// computeMachineFingerprint returns a stable, per-machine identity string for
// forensic audit purposes.  It is sent in the enrollment Tags map alongside
// hardware_id so the server can record which physical machine used a token.
//
// Formula: hex(SHA-256( hostname + "|" + first_non_loopback_MAC + "|" + runtime.GOOS ))
//
// Falls back gracefully: if MAC enumeration fails, the MAC component is "".
// The fingerprint is NOT a secret — it is a forensic correlation identifier.
func computeMachineFingerprint(hostname string) string {
	mac := firstNonLoopbackMAC()
	raw := hostname + "|" + mac + "|" + runtime.GOOS
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// firstNonLoopbackMAC returns the hardware MAC address of the first
// non-loopback, non-virtual network interface, or "" if none is found.
func firstNonLoopbackMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}

// Note: FetchAndDecryptToken, writeSentinelFile, and aesDecryptToken were
// removed — they were the client side of the split-key architecture.
// Legacy aesDecryptToken is kept in cmd/agent/main.go for backward compat
// with old binaries that still have EmbeddedTokenEnc + EmbeddedTokenKey.

