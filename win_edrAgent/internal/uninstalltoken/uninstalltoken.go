// Package uninstalltoken verifies offline uninstall tokens on the agent.
//
// A token authorises removing ONE specific agent while it is offline. The
// server signs it with an Ed25519 private key; the agent verifies it with the
// matching public key embedded at build time. Because only the PUBLIC key is in
// the binary, an attacker who extracts it cannot forge a token.
//
// Wire format (identical to the server's security.SignUninstallToken):
//
//	token = base64url(payloadJSON) + "." + base64url(ed25519Signature)
//
// The agent verifies the signature over the RECEIVED payload bytes (it never
// re-marshals), so there is no canonicalization mismatch between signer and
// verifier.
//
// This package is platform-neutral (pure stdlib) so it can be unit-tested
// without the Windows/CGO build.
package uninstalltoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the token schema version this agent understands. Must match the
// server's security.UninstallTokenVersion.
const Version = 1

// Action is the only action an uninstall token may carry.
const Action = "uninstall"

// clockSkew tolerates small clock differences between server and endpoint.
const clockSkew = 2 * time.Minute

// b64 is the URL-safe, unpadded base64 used for both token segments. It MUST
// match the server's encoding (base64.RawURLEncoding).
var b64 = base64.RawURLEncoding

// pubKeyB64 is the standard-base64 encoding used for the embedded public key,
// matching the server's security.UninstallPublicKeyBase64 (base64.StdEncoding).
var pubKeyB64 = base64.StdEncoding

// Claims is the signed payload. Field names/tags MUST stay byte-identical to the
// server's security.UninstallTokenClaims.
type Claims struct {
	V         int    `json:"v"`
	AgentID   string `json:"agent_id"`
	Action    string `json:"action"`
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// Sentinel errors so callers (and tests) can distinguish failure modes.
var (
	ErrNoPublicKey  = errors.New("no uninstall public key embedded in this build")
	ErrMalformed    = errors.New("malformed uninstall token")
	ErrBadSignature = errors.New("uninstall token signature is invalid")
	ErrWrongAgent   = errors.New("uninstall token is for a different agent")
	ErrExpired      = errors.New("uninstall token has expired")
	ErrNotYetValid  = errors.New("uninstall token is not valid yet")
	ErrWrongAction  = errors.New("uninstall token has an unexpected action")
	ErrWrongVersion = errors.New("uninstall token has an unsupported version")
	ErrEmptyToken   = errors.New("uninstall token is empty")
)

// ParsePublicKey decodes a standard-base64 raw Ed25519 public key (as embedded
// at build time). Returns ErrNoPublicKey when empty.
func ParsePublicKey(embedded string) (ed25519.PublicKey, error) {
	embedded = strings.TrimSpace(embedded)
	if embedded == "" {
		return nil, ErrNoPublicKey
	}
	raw, err := pubKeyB64.DecodeString(embedded)
	if err != nil {
		return nil, fmt.Errorf("decode embedded public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("embedded public key wrong size: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Verify checks token against the embedded public key and the local agent ID.
// On success it returns the parsed claims. localAgentID must be this machine's
// server-assigned agent UUID. now is injectable for testing; pass time.Now().
func Verify(embeddedPubKey, token, localAgentID string, now time.Time) (*Claims, error) {
	pub, err := ParsePublicKey(embeddedPubKey)
	if err != nil {
		return nil, err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrEmptyToken
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrMalformed
	}
	payload, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}

	// Verify the signature over the exact received payload bytes BEFORE trusting
	// any field inside it.
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, payload, sig) {
		return nil, ErrBadSignature
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}

	if claims.V != Version {
		return nil, ErrWrongVersion
	}
	if claims.Action != Action {
		return nil, ErrWrongAction
	}
	if localAgentID == "" || !strings.EqualFold(claims.AgentID, localAgentID) {
		return nil, ErrWrongAgent
	}
	if claims.ExpiresAt > 0 && now.After(time.Unix(claims.ExpiresAt, 0).Add(clockSkew)) {
		return nil, ErrExpired
	}
	if claims.IssuedAt > 0 && now.Before(time.Unix(claims.IssuedAt, 0).Add(-clockSkew)) {
		return nil, ErrNotYetValid
	}
	return &claims, nil
}
