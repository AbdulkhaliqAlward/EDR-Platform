// Package grpcclient provides mTLS certificate management.
package grpcclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/logging"
)

// CertManager handles agent certificate lifecycle.
type CertManager struct {
	logger       *logging.Logger
	certDir      string
	certPath     string
	keyPath      string      // legacy plaintext path (migration only)
	dpapiKeyPath string      // DPAPI-encrypted private key blob
	caPath       string
	tokenPath    string

	// Loaded credentials
	cert       *tls.Certificate
	caCertPool *x509.CertPool
}

// NewCertManager creates a new certificate manager with a cert directory;
// paths are derived as client.crt, private.key, ca-chain.crt under certDir.
func NewCertManager(certDir string, logger *logging.Logger) *CertManager {
	if certDir == "" {
		certDir = "C:\\ProgramData\\EDR"
	}

	return &CertManager{
		logger:       logger,
		certDir:      certDir,
		certPath:     filepath.Join(certDir, "client.crt"),
		keyPath:      filepath.Join(certDir, "private.key"),
		dpapiKeyPath: filepath.Join(certDir, "private.key.dpapi"),
		caPath:       filepath.Join(certDir, "ca-chain.crt"),
		tokenPath:    filepath.Join(certDir, "bootstrap.token"),
	}
}

// NewCertManagerFromConfig creates a certificate manager with paths taken from config.
// certPath, keyPath, and caPath are set from cfg.Certs; certDir is the directory
// of the cert file (used by EnsureDirectories). GenerateCSR and SaveCertificate use only these internal paths.
func NewCertManagerFromConfig(cfg *config.Config, logger *logging.Logger) *CertManager {
	defaultDir := "C:\\ProgramData\\EDR"
	certPath := filepath.Join(defaultDir, "client.crt")
	keyPath := filepath.Join(defaultDir, "private.key")
	caPath := filepath.Join(defaultDir, "ca-chain.crt")

	if cfg != nil {
		if cfg.Certs.CertPath != "" {
			certPath = cfg.Certs.CertPath
		}
		if cfg.Certs.KeyPath != "" {
			keyPath = cfg.Certs.KeyPath
		}
		if cfg.Certs.CAPath != "" {
			caPath = cfg.Certs.CAPath
		}
	}

	certDir := filepath.Dir(certPath)
	tokenPath := filepath.Join(certDir, "bootstrap.token")
	dpapiKeyPath := keyPath + ".dpapi"

	return &CertManager{
		logger:       logger,
		certDir:      certDir,
		certPath:     certPath,
		keyPath:      keyPath,
		dpapiKeyPath: dpapiKeyPath,
		caPath:       caPath,
		tokenPath:    tokenPath,
	}
}

// EnsureDirectories creates required directories.
func (m *CertManager) EnsureDirectories() error {
	if err := os.MkdirAll(m.certDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}
	return nil
}

// HasValidCertificate checks if a valid certificate exists.
func (m *CertManager) HasValidCertificate() bool {
	// Check if cert file exists
	if _, err := os.Stat(m.certPath); os.IsNotExist(err) {
		return false
	}
	// Check if DPAPI key or plaintext key exists
	hasDPAPI := false
	if _, err := os.Stat(m.dpapiKeyPath); err == nil {
		hasDPAPI = true
	}
	if !hasDPAPI {
		if _, err := os.Stat(m.keyPath); os.IsNotExist(err) {
			return false
		}
	}

	// Try to load and validate via DPAPI path
	cert, err := loadKeyPairDPAPI(m.certPath, m.dpapiKeyPath, m.keyPath)
	if err != nil {
		m.logger.Debugf("Failed to load certificate: %v", err)
		return false
	}

	// Check expiration
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}

		// Certificate should be valid for at least 30 days
		if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
			m.logger.Warn("Certificate expires within 30 days")
			return false
		}
	}

	return true
}

// LoadCertificate loads existing certificate and DPAPI-protected private key.
func (m *CertManager) LoadCertificate() error {
	// Load client certificate + private key via DPAPI (auto-migrates plaintext if needed).
	cert, err := loadKeyPairDPAPI(m.certPath, m.dpapiKeyPath, m.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	m.cert = &cert

	// Load CA chain
	caCert, err := os.ReadFile(m.caPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	m.caCertPool = x509.NewCertPool()
	if !m.caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Log certificate info
	if len(cert.Certificate) > 0 {
		x509Cert, _ := x509.ParseCertificate(cert.Certificate[0])
		if x509Cert != nil {
			m.logger.Infof("Certificate loaded: subject=%s expires=%s",
				x509Cert.Subject.CommonName,
				x509Cert.NotAfter.Format("2006-01-02"))
		}
	}

	return nil
}

// GetTLSConfig returns TLS configuration for gRPC.
func (m *CertManager) GetTLSConfig() (*tls.Config, error) {
	if m.cert == nil || m.caCertPool == nil {
		if err := m.LoadCertificate(); err != nil {
			return nil, err
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*m.cert},
		RootCAs:      m.caCertPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// GenerateCSR creates a Certificate Signing Request.
func (m *CertManager) GenerateCSR(agentID, hostname string) ([]byte, error) {
	m.logger.Info("Generating RSA key pair...")

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         agentID,
			Organization:       []string{"MITRAS"},
			OrganizationalUnit: []string{"Agents"},
		},
		DNSNames: []string{hostname},
	}

	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Save private key
	if err := m.savePrivateKey(privateKey); err != nil {
		return nil, err
	}

	// Encode CSR as PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	m.logger.Infof("CSR generated for agent: %s", agentID)
	return csrPEM, nil
}

// savePrivateKey encrypts the private key with DPAPI and saves the blob to disk.
// No plaintext key file is ever written. The keyPEM is zeroed in memory.
func (m *CertManager) savePrivateKey(key *rsa.PrivateKey) error {
	if err := m.EnsureDirectories(); err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Zero the raw DER bytes immediately — we only need the PEM.
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	// Encrypt with DPAPI and save — keyPEM is zeroed inside savePrivateKeyDPAPI.
	if err := savePrivateKeyDPAPI(keyPEM, m.dpapiKeyPath); err != nil {
		return err
	}

	m.logger.Debug("Private key saved (DPAPI-protected)")
	return nil
}

// SaveCertificate saves the signed certificate.
func (m *CertManager) SaveCertificate(certPEM, caCertPEM []byte) error {
	if err := m.EnsureDirectories(); err != nil {
		return err
	}

	// Save client certificate
	if err := os.WriteFile(m.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Save CA chain
	if err := os.WriteFile(m.caPath, caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA chain: %w", err)
	}

	m.logger.Info("Certificate and CA chain saved")
	return nil
}

// GetBootstrapToken reads the bootstrap token.
func (m *CertManager) GetBootstrapToken() (string, error) {
	data, err := os.ReadFile(m.tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read bootstrap token: %w", err)
	}
	return string(data), nil
}

// DeleteBootstrapToken removes the bootstrap token after use.
func (m *CertManager) DeleteBootstrapToken() error {
	if err := os.Remove(m.tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete bootstrap token: %w", err)
	}
	m.logger.Info("Bootstrap token deleted")
	return nil
}

// GetCertificateExpiry returns when the certificate expires.
func (m *CertManager) GetCertificateExpiry() (time.Time, error) {
	if m.cert == nil {
		if err := m.LoadCertificate(); err != nil {
			return time.Time{}, err
		}
	}

	if len(m.cert.Certificate) == 0 {
		return time.Time{}, fmt.Errorf("no certificate loaded")
	}

	x509Cert, err := x509.ParseCertificate(m.cert.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}

	return x509Cert.NotAfter, nil
}

// NeedsRenewal checks if certificate needs renewal.
func (m *CertManager) NeedsRenewal() bool {
	expiry, err := m.GetCertificateExpiry()
	if err != nil {
		return true // Force renewal on error
	}

	// Renew if expires within 90 days
	return time.Now().Add(90 * 24 * time.Hour).After(expiry)
}
