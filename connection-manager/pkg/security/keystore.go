// Package security — KeyStore provides encrypted-at-rest storage for server
// private keys (ca.key, server.key, jwt_private.pem).
//
// Encryption scheme:
//
//	KEK derivation: Argon2id(passphrase, salt) → 256-bit AES key
//	File encryption: AES-256-GCM(nonce ∥ ciphertext ∥ tag)
//	Salt: 16 bytes, stored once in .keystore.salt
//
// On first startup plaintext key files are encrypted → .enc and originals deleted.
// On subsequent startups .enc files are decrypted directly into memory.
package security

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — OWASP recommended minimum for password hashing.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256
	saltLen       = 16
	saltFile      = ".keystore.salt"
)

// KeyStorePaths holds filesystem paths for every key/cert file managed by the
// KeyStore. Public files (certs, public keys) are NOT encrypted.
type KeyStorePaths struct {
	CACertPath     string
	CAKeyPath      string
	ServerCertPath string
	ServerKeyPath  string
	JWTPrivatePath string
	JWTPublicPath  string
	// Uninstall-token Ed25519 signing key. Optional: when empty, offline
	// uninstall tokens are simply unavailable (feature degrades, server still runs).
	UninstallKeyPath string
	UninstallPubPath string
}

// KeyStore holds decrypted key material in memory and manages the encrypted-
// at-rest lifecycle. All getters are thread-safe.
type KeyStore struct {
	mu sync.RWMutex

	// In-memory key material (never written to disk after initial encryption).
	caCert    *x509.Certificate
	caKey     crypto.Signer
	caCertPEM []byte

	serverCert tls.Certificate // combined cert + key

	jwtPrivateKey *rsa.PrivateKey
	jwtPublicKey  *rsa.PublicKey

	// Ed25519 signing key for offline uninstall tokens. May be nil when the
	// feature is not configured or key loading failed (non-fatal).
	uninstallSignKey ed25519.PrivateKey
	uninstallPubRaw  []byte // raw 32-byte Ed25519 public key (for build-time embedding)

	// Derived key-encryption key.
	kek []byte

	paths  KeyStorePaths
	logger *logrus.Logger
}

// NewKeyStore creates a KeyStore. Call Initialize() to perform the actual
// key loading / migration / generation.
func NewKeyStore(passphrase string, paths KeyStorePaths, logger *logrus.Logger) (*KeyStore, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("MASTER_KEY_PASSPHRASE environment variable is required for encrypted key storage")
	}
	return &KeyStore{
		paths:  paths,
		logger: logger,
	}, nil
}

// Initialize loads (or migrates) all private keys into memory.
//
// Lifecycle per private-key file:
//  1. .enc exists → decrypt into memory
//  2. plaintext exists → read, encrypt → .enc, delete plaintext
//  3. neither exists → generate via existing certgen helpers, then encrypt
//
// Public files (ca.crt, server.crt, jwt_public.pem) remain plaintext on disk.
func (ks *KeyStore) Initialize(passphrase string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// ── 1. Derive KEK ────────────────────────────────────────────────────
	salt, err := ks.ensureSalt()
	if err != nil {
		return fmt.Errorf("keystore salt: %w", err)
	}
	ks.kek = argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	ks.logger.Info("KeyStore: KEK derived via Argon2id")

	// ── 2. CA key + cert ─────────────────────────────────────────────────
	caKeyPEM, err := ks.loadPrivateKey(ks.paths.CAKeyPath)
	if err != nil {
		// Neither .enc nor plaintext exist → generate CA.
		ks.logger.Info("KeyStore: CA key not found — generating new Root CA...")
		if _, genErr := EnsureCA(ks.paths.CACertPath, ks.paths.CAKeyPath, ks.logger); genErr != nil {
			return fmt.Errorf("keystore: generate CA: %w", genErr)
		}
		caKeyPEM, err = ks.migrateKeyFile(ks.paths.CAKeyPath)
		if err != nil {
			return fmt.Errorf("keystore: migrate CA key: %w", err)
		}
	}
	ks.caKey, err = parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("keystore: parse CA key: %w", err)
	}

	ks.caCertPEM, err = os.ReadFile(ks.paths.CACertPath)
	if err != nil {
		return fmt.Errorf("keystore: read CA cert: %w", err)
	}
	ks.caCert, err = parseCertPEM(ks.caCertPEM)
	if err != nil {
		return fmt.Errorf("keystore: parse CA cert: %w", err)
	}

	// Validate the CA pair matches.
	if !caKeyMatchesCert(ks.caCert, ks.caKey) {
		return fmt.Errorf("keystore: CA cert and key do not form a valid pair")
	}
	ks.logger.Info("KeyStore: CA key loaded and validated")

	// ── 3. Server cert + key ─────────────────────────────────────────────
	if err := ks.ensureServerCert(); err != nil {
		return fmt.Errorf("keystore: server cert: %w", err)
	}
	ks.logger.Info("KeyStore: Server TLS certificate loaded")

	// ── 4. JWT keys ──────────────────────────────────────────────────────
	jwtPrivPEM, err := ks.loadPrivateKey(ks.paths.JWTPrivatePath)
	if err != nil {
		ks.logger.Info("KeyStore: JWT keys not found — generating RSA 2048 keypair...")
		if _, genErr := EnsureJWTKeys(ks.paths.JWTPrivatePath, ks.paths.JWTPublicPath, ks.logger); genErr != nil {
			return fmt.Errorf("keystore: generate JWT keys: %w", genErr)
		}
		jwtPrivPEM, err = ks.migrateKeyFile(ks.paths.JWTPrivatePath)
		if err != nil {
			return fmt.Errorf("keystore: migrate JWT private key: %w", err)
		}
	}
	privSigner, err := parsePrivateKeyPEM(jwtPrivPEM)
	if err != nil {
		return fmt.Errorf("keystore: parse JWT private key: %w", err)
	}
	rsaPriv, ok := privSigner.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("keystore: JWT private key is not RSA (got %T)", privSigner)
	}
	ks.jwtPrivateKey = rsaPriv
	ks.jwtPublicKey = &rsaPriv.PublicKey

	ks.logger.Info("KeyStore: JWT keys loaded")

	// ── 5. Uninstall-token signing key (Ed25519) — OPTIONAL, non-fatal ───
	// A failure here must never prevent the server from starting; it only
	// disables minting of offline uninstall tokens.
	if ks.paths.UninstallKeyPath != "" {
		if err := ks.ensureUninstallSigningKey(); err != nil {
			ks.logger.Warnf("KeyStore: uninstall-token signing key unavailable (offline uninstall disabled): %v", err)
		} else {
			ks.logger.Info("KeyStore: uninstall-token signing key loaded")
		}
	}

	ks.logger.Info("KeyStore: all private keys encrypted at rest ✓")

	return nil
}

// ensureUninstallSigningKey loads (or generates then encrypts) the Ed25519
// key used to sign offline uninstall tokens. The private key is encrypted at
// rest exactly like the JWT/CA keys. The 32-byte public key is cached for
// build-time embedding into agent binaries.
func (ks *KeyStore) ensureUninstallSigningKey() error {
	privPEM, err := ks.loadPrivateKey(ks.paths.UninstallKeyPath)
	if err != nil {
		if _, genErr := EnsureUninstallSigningKey(ks.paths.UninstallKeyPath, ks.paths.UninstallPubPath, ks.logger); genErr != nil {
			return fmt.Errorf("generate: %w", genErr)
		}
		privPEM, err = ks.migrateKeyFile(ks.paths.UninstallKeyPath)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	signer, err := parsePrivateKeyPEM(privPEM)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	edPriv, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("uninstall key is not Ed25519 (got %T)", signer)
	}
	edPub, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("cannot derive Ed25519 public key")
	}

	ks.uninstallSignKey = edPriv
	ks.uninstallPubRaw = append([]byte(nil), edPub...)
	return nil
}

// UninstallSigningKey returns the Ed25519 private key for signing offline
// uninstall tokens, or nil when the feature is unavailable.
func (ks *KeyStore) UninstallSigningKey() ed25519.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.uninstallSignKey
}

// UninstallPublicKeyBase64 returns the standard-base64 raw 32-byte Ed25519
// public key for embedding into agent binaries at build time, or "" when the
// feature is unavailable.
func (ks *KeyStore) UninstallPublicKeyBase64() string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if len(ks.uninstallPubRaw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ks.uninstallPubRaw)
}

// ─── Getters (thread-safe) ───────────────────────────────────────────────────

// CACert returns the parsed CA certificate.
func (ks *KeyStore) CACert() *x509.Certificate {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.caCert
}

// CAKey returns the CA private key signer.
func (ks *KeyStore) CAKey() crypto.Signer {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.caKey
}

// CACertPEM returns the PEM-encoded CA certificate.
func (ks *KeyStore) CACertPEM() []byte {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.caCertPEM
}

// ServerTLSCert returns the server TLS certificate (cert + key combined).
func (ks *KeyStore) ServerTLSCert() tls.Certificate {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.serverCert
}

// JWTPrivateKey returns the RSA private key used for JWT signing.
func (ks *KeyStore) JWTPrivateKey() *rsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.jwtPrivateKey
}

// JWTPublicKey returns the RSA public key used for JWT verification.
func (ks *KeyStore) JWTPublicKey() *rsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.jwtPublicKey
}

// ─── Server cert lifecycle (IP SAN check + chain validation) ─────────────────

func (ks *KeyStore) ensureServerCert() error {
	serverKeyPEM, err := ks.loadPrivateKey(ks.paths.ServerKeyPath)

	if err != nil {
		// No encrypted or plaintext key — generate fresh.
		ks.logger.Info("KeyStore: Server cert/key not found — generating...")
		hostIPs, ipErr := discoverHostIPs()
		if ipErr != nil {
			return fmt.Errorf("discover host IPs: %w", ipErr)
		}
		if genErr := generateServerCert(ks.caCert, ks.caKey, ks.paths.ServerCertPath, ks.paths.ServerKeyPath, hostIPs); genErr != nil {
			return fmt.Errorf("generate server cert: %w", genErr)
		}
		serverKeyPEM, err = ks.migrateKeyFile(ks.paths.ServerKeyPath)
		if err != nil {
			return err
		}
	}

	// Check IP SANs — regenerate if host IPs changed.
	hostIPs, ipErr := discoverHostIPs()
	if ipErr != nil {
		return fmt.Errorf("discover host IPs: %w", ipErr)
	}

	if !certCoversIPs(ks.paths.ServerCertPath, hostIPs, ks.logger) {
		ks.logger.Info("KeyStore: Server cert does not cover current IPs — regenerating...")
		if genErr := generateServerCert(ks.caCert, ks.caKey, ks.paths.ServerCertPath, ks.paths.ServerKeyPath, hostIPs); genErr != nil {
			return fmt.Errorf("regenerate server cert: %w", genErr)
		}
		serverKeyPEM, err = ks.migrateKeyFile(ks.paths.ServerKeyPath)
		if err != nil {
			return err
		}
	}

	// Validate trust chain.
	if chainErr := validateServerCertChain(ks.paths.CACertPath, ks.paths.ServerCertPath, ks.logger); chainErr != nil {
		ks.logger.Warnf("KeyStore: Server cert chain invalid (%v) — regenerating...", chainErr)
		_ = os.Remove(ks.paths.ServerCertPath)
		if genErr := generateServerCert(ks.caCert, ks.caKey, ks.paths.ServerCertPath, ks.paths.ServerKeyPath, hostIPs); genErr != nil {
			return fmt.Errorf("regenerate server cert (chain fix): %w", genErr)
		}
		serverKeyPEM, err = ks.migrateKeyFile(ks.paths.ServerKeyPath)
		if err != nil {
			return err
		}
	}

	// Build tls.Certificate from on-disk cert (public) + in-memory key.
	serverCertPEM, err := os.ReadFile(ks.paths.ServerCertPath)
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}
	ks.serverCert, err = tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("build TLS keypair: %w", err)
	}

	return nil
}

// ─── Encrypted file I/O ─────────────────────────────────────────────────────

// loadPrivateKey tries (1) .enc file → decrypt, (2) plaintext → migrate.
// Returns PEM bytes or error if neither source exists.
func (ks *KeyStore) loadPrivateKey(plaintextPath string) ([]byte, error) {
	encPath := plaintextPath + ".enc"

	// 1. Try encrypted file.
	if ciphertext, err := os.ReadFile(encPath); err == nil {
		plain, decErr := ks.decrypt(ciphertext)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt %s: %w", encPath, decErr)
		}
		ks.logger.Debugf("KeyStore: loaded encrypted key %s", filepath.Base(encPath))
		return plain, nil
	}

	// 2. Try plaintext → migrate.
	return ks.migrateKeyFile(plaintextPath)
}

// migrateKeyFile reads a plaintext key, encrypts it to .enc, deletes original.
func (ks *KeyStore) migrateKeyFile(plaintextPath string) ([]byte, error) {
	data, err := os.ReadFile(plaintextPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", plaintextPath, err)
	}

	encPath := plaintextPath + ".enc"
	if err := ks.encryptAndSave(data, encPath); err != nil {
		return nil, fmt.Errorf("encrypt %s: %w", filepath.Base(plaintextPath), err)
	}

	if err := os.Remove(plaintextPath); err != nil && !os.IsNotExist(err) {
		ks.logger.Warnf("KeyStore: failed to delete plaintext %s: %v", filepath.Base(plaintextPath), err)
	} else {
		ks.logger.Infof("KeyStore: migrated %s → %s (plaintext deleted)", filepath.Base(plaintextPath), filepath.Base(encPath))
	}

	return data, nil
}

func (ks *KeyStore) encryptAndSave(plaintext []byte, encPath string) error {
	block, err := aes.NewCipher(ks.kek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(encPath, ciphertext, 0600)
}

func (ks *KeyStore) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ks.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

// ensureSalt loads or creates the Argon2id salt file.
func (ks *KeyStore) ensureSalt() ([]byte, error) {
	dir := filepath.Dir(ks.paths.CAKeyPath) // certs directory
	path := filepath.Join(dir, saltFile)

	if data, err := os.ReadFile(path); err == nil && len(data) == saltLen {
		return data, nil
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, salt, 0600); err != nil {
		return nil, err
	}
	ks.logger.Info("KeyStore: new Argon2id salt generated")
	return salt, nil
}

// ─── PEM parsing helpers ────────────────────────────────────────────────────

func parsePrivateKeyPEM(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key does not implement crypto.Signer (got %T)", key)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

func parseCertPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func caKeyMatchesCert(cert *x509.Certificate, key crypto.Signer) bool {
	certPubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	keyPubBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return false
	}
	return string(certPubBytes) == string(keyPubBytes)
}

// ─── Unused import guards ───────────────────────────────────────────────────

var _ = (*ecdsa.PrivateKey)(nil) // used in parsePrivateKeyPEM via x509.ParseECPrivateKey
