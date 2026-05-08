// Package security provides TLS/mTLS configuration for the gRPC server.
package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// TLSConfig holds configuration for TLS setup.
type TLSConfig struct {
	CertPath   string
	KeyPath    string
	CACertPath string

	// Optional: Additional trusted CAs for client verification
	ClientCAs []string

	// TLS options
	MinVersion uint16 // Default TLS 1.3 (tls.VersionTLS13)
}

// LoadServerTLSConfig loads TLS configuration for the gRPC server with mTLS support.
// ClientAuth is set to VerifyClientCertIfGiven so that the TLS handshake succeeds
// without a client certificate (allowing new agents to connect and call RegisterAgent
// with a bootstrap token). The auth interceptor then requires a valid client cert
// for all RPCs except RegisterAgent.
func LoadServerTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load additional client CAs if provided
	for _, caPath := range cfg.ClientCAs {
		additionalCA, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read additional CA %s: %w", caPath, err)
		}
		if !caPool.AppendCertsFromPEM(additionalCA) {
			logrus.Warnf("Failed to parse additional CA certificate: %s", caPath)
		}
	}

	minVersion := cfg.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS13 // Enforce TLS 1.3 by default
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven, // Allow handshake without client cert for RegisterAgent bootstrap
		MinVersion:   minVersion,

		// Strong cipher suites for TLS 1.3
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},

		// Prefer server cipher suites
		PreferServerCipherSuites: true,
	}

	return tlsConfig, nil
}

// LoadServerTLSConfigFromMemory builds the same mTLS tls.Config as
// LoadServerTLSConfig but uses an in-memory tls.Certificate (from the
// KeyStore) and raw CA PEM bytes instead of reading files from disk.
func LoadServerTLSConfigFromMemory(serverCert tls.Certificate, caCertPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,

		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},

		PreferServerCipherSuites: true,
	}
	return tlsConfig, nil
}

// LoadClientTLSConfig loads TLS configuration for gRPC clients.
func LoadClientTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate for server verification
	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	minVersion := cfg.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS13
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   minVersion,
	}, nil
}

// ExtractAgentIDFromCert extracts the agent ID from the certificate's SAN (Subject Alternative Name).
// The agent ID is expected to be in the DNS names or URI SANs.
func ExtractAgentIDFromCert(cert *x509.Certificate) (string, error) {
	// First, check DNS names
	for _, dnsName := range cert.DNSNames {
		// Agent ID might be in format: agent-{uuid}.edr.local
		if len(dnsName) > 6 && dnsName[:6] == "agent-" {
			return dnsName[6:], nil
		}
	}

	// Check URI SANs (format: urn:edr:agent:{uuid})
	for _, uri := range cert.URIs {
		if uri.Scheme == "urn" && uri.Opaque != "" {
			// Parse urn:edr:agent:{uuid}
			if len(uri.Opaque) > 10 && uri.Opaque[:10] == "edr:agent:" {
				return uri.Opaque[10:], nil
			}
		}
	}

	// Check Common Name as fallback
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}

	return "", fmt.Errorf("agent ID not found in certificate")
}

// ValidateCertificateChain validates a certificate against the CA chain.
func ValidateCertificateChain(cert *x509.Certificate, caPool *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots: caPool,
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

// IsCertificateExpiringSoon checks if the certificate will expire within the given number of days.
func IsCertificateExpiringSoon(cert *x509.Certificate, within int) bool {
	expiryThreshold := time.Now().AddDate(0, 0, within)
	return cert.NotAfter.Before(expiryThreshold)
}
