// Package service provides the business logic layer.
package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// CertificateService provides business logic for certificate operations.
type CertificateService interface {
	// Issue issues a new certificate from a CSR.
	Issue(ctx context.Context, agentID uuid.UUID, csrPEM []byte) (*IssuedCertificate, error)

	// Renew renews an existing certificate.
	Renew(ctx context.Context, agentID uuid.UUID, csrPEM []byte, oldFingerprint string) (*IssuedCertificate, error)

	// Revoke revokes a certificate.
	Revoke(ctx context.Context, certID uuid.UUID, revokedBy uuid.UUID, reason string) error

	// GetActive gets the active certificate for an agent.
	GetActive(ctx context.Context, agentID uuid.UUID) (*models.Certificate, error)

	// IsRevoked checks if a certificate fingerprint is revoked.
	IsRevoked(ctx context.Context, fingerprint string) (bool, error)
}

// IssuedCertificate contains an issued certificate and metadata.
type IssuedCertificate struct {
	Certificate  []byte
	CACert       []byte
	Fingerprint  string
	SerialNumber string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// certServiceImpl implements CertificateService.
type certServiceImpl struct {
	certRepo  repository.CertificateRepository
	agentRepo repository.AgentRepository
	auditRepo repository.AuditLogRepository
	redis     *cache.RedisClient
	logger    *logrus.Logger

	// CA configuration: paths to Root CA cert and private key (for signing agent CSRs)
	caCertPath string
	caKeyPath  string
	caCert     *x509.Certificate
	caKey      interface{}
	caCertPEM  []byte // PEM-encoded CA cert to return in IssuedCertificate.CACert
	validDays  int
}

// NewCertificateService creates a new CertificateService.
// caCertPath and caKeyPath are paths to the Root CA certificate and private key (PEM).
// If both are non-empty, they are loaded at construction and used to sign agent CSRs.
func NewCertificateService(
	certRepo repository.CertificateRepository,
	agentRepo repository.AgentRepository,
	auditRepo repository.AuditLogRepository,
	redis *cache.RedisClient,
	logger *logrus.Logger,
	caCertPath, caKeyPath string,
) CertificateService {
	s := &certServiceImpl{
		certRepo:   certRepo,
		agentRepo:  agentRepo,
		auditRepo:  auditRepo,
		redis:      redis,
		logger:     logger,
		caCertPath: caCertPath,
		caKeyPath:  caKeyPath,
		validDays:  90,
	}
	if caCertPath != "" && caKeyPath != "" {
		if err := s.loadCA(); err != nil {
			logger.WithError(err).Warn("CA not loaded; certificate issuance will fail until CA paths are set")
		}
	}
	return s
}

// NewCertificateServiceWithKeys creates a CertificateService using pre-loaded
// CA key material from the KeyStore (encrypted at rest). This avoids reading
// ca.key and ca.crt from disk at runtime.
func NewCertificateServiceWithKeys(
	certRepo repository.CertificateRepository,
	agentRepo repository.AgentRepository,
	auditRepo repository.AuditLogRepository,
	redis *cache.RedisClient,
	logger *logrus.Logger,
	caCert *x509.Certificate,
	caKey interface{},
	caCertPEM []byte,
) CertificateService {
	return &certServiceImpl{
		certRepo:  certRepo,
		agentRepo: agentRepo,
		auditRepo: auditRepo,
		redis:     redis,
		logger:    logger,
		caCert:    caCert,
		caKey:     caKey,
		caCertPEM: caCertPEM,
		validDays: 90,
	}
}

// loadCA loads the Root CA certificate and private key from disk.
func (s *certServiceImpl) loadCA() error {
	caCertPEM, err := os.ReadFile(s.caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in CA cert")
	}
	s.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}
	s.caCertPEM = caCertPEM

	caKeyPEM, err := os.ReadFile(s.caKeyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in CA key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		s.caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		s.caKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return fmt.Errorf("unsupported CA key type: %s", block.Type)
	}
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}
	s.logger.Info("CA certificate and key loaded for agent certificate issuance")
	return nil
}

// Issue issues a new certificate from a CSR by signing it with the Root CA.
func (s *certServiceImpl) Issue(ctx context.Context, agentID uuid.UUID, csrPEM []byte) (*IssuedCertificate, error) {
	if s.caCert == nil || s.caKey == nil {
		s.logger.Error("CA not loaded; cannot sign CSR")
		return nil, fmt.Errorf("certificate issuance not configured: CA certificate or key not loaded")
	}

	// 1. Parse CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrInvalidCSR
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		s.logger.WithError(err).Error("Failed to parse CSR")
		return nil, ErrInvalidCSR
	}

	// 2. Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		s.logger.WithError(err).Error("Invalid CSR signature")
		return nil, ErrInvalidCSR
	}

	// 3. Server-Authoritative Identity Binding
	//
	// The CSR's Subject.CommonName is NOT trusted. During First-Touch
	// Provisioning the agent cannot know its server-assigned UUID when it
	// generates the CSR, so the CN will typically be the agent's hostname
	// (e.g. "win10-victim-pc"). This is expected and NOT a security issue
	// because:
	//   a) The server-controlled certificate template (below) ALWAYS overrides
	//      the Subject to "agent-<UUID>" — the CSR's requested CN never makes
	//      it into the signed certificate.
	//   b) All SANs from the CSR are discarded; only the server-determined
	//      DNS SAN "agent-<UUID>" is placed in the final certificate.
	//   c) Only the public key is extracted from the CSR.
	//
	// We log the original CN for audit purposes only.
	expectedCN := "agent-" + agentID.String()
	if csr.Subject.CommonName != expectedCN {
		s.logger.WithFields(logrus.Fields{
			"agent_id":     agentID,
			"requested_cn": csr.Subject.CommonName,
			"assigned_cn":  expectedCN,
		}).Info("CSR CN differs from assigned agent identity (expected during first-touch enrollment) — CA will override Subject in certificate")
	}

	// 4. SAN Policy: CSR-requested SANs are stripped (logged for audit).
	//    The certificate template sets the sole DNS SAN to "agent-<UUID>".
	allowedDNS := expectedCN
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		s.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"dns_sans": csr.DNSNames,
			"ip_sans":  csr.IPAddresses,
			"uri_sans": csr.URIs,
		}).Info("CSR contains SANs that will be discarded — certificate template overrides all SANs")
	}

	// 5. Build certificate template — server-controlled, ignoring all CSR extensions
	now := time.Now()
	expiresAt := now.AddDate(0, 0, s.validDays)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrInternal
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   expectedCN,
			Organization: []string{"EDR Agent"},
		},
		NotBefore:   now,
		NotAfter:    expiresAt,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{allowedDNS},

		// CRITICAL: Force leaf certificate — block CA escalation (CM-C4)
		// NOTE: MaxPathLen / MaxPathLenZero must NOT be set on non-CA certs;
		// Go's crypto/x509 rejects them with "only CAs are allowed to specify MaxPathLen".
		BasicConstraintsValid: true,
		IsCA:                  false,

		// No IP SANs, no URI SANs, no extra extensions from CSR
		IPAddresses:     []net.IP{},
		ExtraExtensions: nil,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to sign certificate")
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	// PEM-encode the signed certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fingerprint := models.GenerateFingerprint(certDER)

	// 4. Store certificate in database (store PEM for consistency)
	cert := &models.Certificate{
		ID:              uuid.New(),
		AgentID:         agentID,
		CertFingerprint: fingerprint,
		PublicKey:       certPEM,
		SerialNumber:    serialNumber.String(),
		Status:          models.CertStatusActive,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
	}

	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.WithError(err).Error("Failed to store certificate")
		return nil, ErrInternal
	}

	// 5. Update agent's current certificate
	agent, err := s.agentRepo.GetByID(ctx, agentID)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to load agent for cert update")
	} else {
		agent.CurrentCertID = &cert.ID
		agent.CertExpiresAt = &expiresAt
		if err := s.agentRepo.Update(ctx, agent); err != nil {
			s.logger.WithError(err).Warn("Failed to update agent current cert")
		}
	}

	// 6. Audit log
	audit := models.NewAuditLog(uuid.Nil, "system", models.AuditActionCertIssued, "certificate", cert.ID)
	audit.WithDetail("agent_id", agentID.String())
	s.auditRepo.Create(ctx, audit)

	s.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"cert_id":  cert.ID,
		"expires":  expiresAt,
	}).Info("Certificate issued")

	return &IssuedCertificate{
		Certificate:  certPEM,
		CACert:       s.caCertPEM,
		Fingerprint:  fingerprint,
		SerialNumber: serialNumber.String(),
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
	}, nil
}

// Renew renews an existing certificate.
func (s *certServiceImpl) Renew(ctx context.Context, agentID uuid.UUID, csrPEM []byte, oldFingerprint string) (*IssuedCertificate, error) {
	// 1. Validate old certificate exists and is active
	oldCert, err := s.certRepo.GetByFingerprint(ctx, oldFingerprint)
	if err != nil {
		return nil, ErrCertNotFound
	}
	if oldCert.Status != models.CertStatusActive {
		return nil, fmt.Errorf("certificate is not active")
	}

	// 2. Issue new certificate
	newCert, err := s.Issue(ctx, agentID, csrPEM)
	if err != nil {
		return nil, err
	}

	// 3. Mark old certificate as superseded
	if err := s.certRepo.MarkSuperseded(ctx, oldCert.ID); err != nil {
		s.logger.WithError(err).Error("Failed to mark old cert as superseded")
	}

	// 4. Audit log
	audit := models.NewAuditLog(uuid.Nil, "system", models.AuditActionCertRenewed, "certificate", oldCert.ID)
	audit.WithDetail("agent_id", agentID.String())
	audit.WithDetail("new_fingerprint", newCert.Fingerprint)
	s.auditRepo.Create(ctx, audit)

	return newCert, nil
}

// Revoke revokes a certificate.
func (s *certServiceImpl) Revoke(ctx context.Context, certID uuid.UUID, revokedBy uuid.UUID, reason string) error {
	cert, err := s.certRepo.GetByID(ctx, certID)
	if err != nil {
		return ErrCertNotFound
	}

	// 1. Revoke in database
	if err := s.certRepo.Revoke(ctx, certID, revokedBy, reason); err != nil {
		return err
	}

	// 2. Add to Redis revocation cache (skip when Redis unavailable)
	if s.redis != nil {
		s.redis.AddCertToRevocationList(ctx, cert.CertFingerprint, cert.ExpiresAt)
	}

	// 3. Audit log
	audit := models.NewAuditLog(revokedBy, "", models.AuditActionCertRevoked, "certificate", certID)
	audit.WithDetail("reason", reason)
	s.auditRepo.Create(ctx, audit)

	s.logger.WithFields(logrus.Fields{
		"cert_id":    certID,
		"revoked_by": revokedBy,
		"reason":     reason,
	}).Info("Certificate revoked")

	return nil
}

// GetActive gets the active certificate for an agent.
func (s *certServiceImpl) GetActive(ctx context.Context, agentID uuid.UUID) (*models.Certificate, error) {
	return s.certRepo.GetActiveByAgentID(ctx, agentID)
}

// IsRevoked checks if a certificate is revoked.
func (s *certServiceImpl) IsRevoked(ctx context.Context, fingerprint string) (bool, error) {
	// Check Redis cache first (skip when Redis unavailable)
	if s.redis != nil {
		revoked, err := s.redis.IsCertRevoked(ctx, fingerprint)
		if err == nil && revoked {
			return true, nil
		}
	}

	// Check database
	cert, err := s.certRepo.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		return false, nil // Not found means not revoked
	}

	return cert.Status == models.CertStatusRevoked, nil
}
