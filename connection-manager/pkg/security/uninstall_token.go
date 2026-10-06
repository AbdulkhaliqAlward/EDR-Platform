// Package security — offline uninstall token.
//
// An uninstall token authorises removing ONE specific agent, even when that
// agent is offline. It is an Ed25519-signed, agent-bound, short-lived claim:
//
//	token = base64url(payloadJSON) + "." + base64url(ed25519Signature)
//
// Security properties:
//   - The server holds the Ed25519 PRIVATE key (encrypted at rest in KeyStore).
//   - The agent embeds only the PUBLIC key at build time — a public key cannot
//     forge tokens, so the binary carries no removal secret.
//   - agent_id binding: a token for one device is rejected by any other.
//   - expires_at: the token is valid only briefly (minutes), limiting reuse.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// UninstallTokenVersion is the current token schema version. The agent rejects
// any version it does not understand.
const UninstallTokenVersion = 1

// UninstallTokenAction is the only action an uninstall token may carry.
const UninstallTokenAction = "uninstall"

// UninstallTokenClaims is the signed payload of an uninstall token.
// Field names are short and fixed because the agent re-declares an identical
// struct; the two JSON shapes MUST stay byte-compatible.
type UninstallTokenClaims struct {
	V         int    `json:"v"`          // schema version
	AgentID   string `json:"agent_id"`   // UUID of the target agent
	Action    string `json:"action"`     // always "uninstall"
	Nonce     string `json:"nonce"`      // random, base64 — makes each token unique
	IssuedAt  int64  `json:"issued_at"`  // unix seconds
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

// b64 is the URL-safe, unpadded base64 encoding used for both token segments.
var b64 = base64.RawURLEncoding

// SignUninstallToken builds and signs an uninstall token for agentID, valid for
// ttl from now. The caller is responsible for all authorization checks (RBAC,
// approval, agent existence) BEFORE minting a token.
func SignUninstallToken(priv ed25519.PrivateKey, agentID string, ttl time.Duration) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("uninstall signing key unavailable")
	}
	if agentID == "" {
		return "", fmt.Errorf("agentID is required")
	}
	if ttl <= 0 {
		return "", fmt.Errorf("ttl must be positive")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now()
	claims := UninstallTokenClaims{
		V:         UninstallTokenVersion,
		AgentID:   agentID,
		Action:    UninstallTokenAction,
		Nonce:     b64.EncodeToString(nonce),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(sig), nil
}

// EnsureUninstallSigningKey generates an Ed25519 keypair at the given paths if
// the private key file does not already exist, writing the private key as
// PKCS#8 PEM (0600) and the public key as PKIX PEM (0644). It returns true when
// it generated a new key. Mirrors EnsureJWTKeys so the KeyStore can encrypt the
// private key at rest with migrateKeyFile.
func EnsureUninstallSigningKey(privateKeyPath, publicKeyPath string, logger *logrus.Logger) (bool, error) {
	if _, err := os.Stat(privateKeyPath); err == nil {
		return false, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, fmt.Errorf("generate uninstall signing key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return false, fmt.Errorf("marshal uninstall private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false, fmt.Errorf("marshal uninstall public key: %w", err)
	}

	if err := os.WriteFile(privateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		return false, fmt.Errorf("write uninstall private key: %w", err)
	}
	if err := os.WriteFile(publicKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		return false, fmt.Errorf("write uninstall public key: %w", err)
	}
	if logger != nil {
		logger.Info("KeyStore: generated new Ed25519 uninstall-token signing key")
	}
	return true, nil
}
