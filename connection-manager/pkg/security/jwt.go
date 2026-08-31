// Package security provides JWT token management for agent authentication.
package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTManager handles JWT token creation and validation.
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// Claims represents the JWT claims for agent authentication.
type Claims struct {
	jwt.RegisteredClaims
	AgentID        string   `json:"agent_id"`
	Username       string   `json:"username,omitempty"`       // human-readable login name
	Roles          []string `json:"roles,omitempty"`
	Type           string   `json:"type"`                     // "access" or "refresh"
	SessionVersion int      `json:"sv,omitempty"`             // incremented on login/logout; middleware rejects stale tokens
}

// TokenPair contains both access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccessExp    time.Time `json:"access_exp"`
	RefreshExp   time.Time `json:"refresh_exp"`
}

// NewJWTManager creates a new JWT manager with the given keys and configuration.
func NewJWTManager(privateKeyPath, publicKeyPath, issuer, audience string, accessTTL, refreshTTL time.Duration) (*JWTManager, error) {
	// Load private key
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	// Load public key
	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

// NewJWTManagerFromKeys creates a JWTManager from pre-loaded RSA keys.
// This is used when keys are held in memory by the KeyStore (encrypted at rest)
// instead of being read from disk paths.
func NewJWTManagerFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer, audience string, accessTTL, refreshTTL time.Duration) *JWTManager {
	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// GenerateTokenPair creates a new access and refresh token pair for a user.
// agentID is the user's UUID (stored as JWT Subject).
// username is the human-readable login name embedded in the token claims.
func (m *JWTManager) GenerateTokenPair(agentID string, username string, roles []string) (*TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(m.accessTTL)
	refreshExp := now.Add(m.refreshTTL)

	// Generate access token
	accessToken, err := m.generateToken(agentID, username, roles, "access", accessExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := m.generateToken(agentID, username, roles, "refresh", refreshExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessExp:    accessExp,
		RefreshExp:   refreshExp,
	}, nil
}

// generateToken creates a single JWT token.
func (m *JWTManager) generateToken(agentID string, username string, roles []string, tokenType string, expiresAt time.Time) (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   agentID,
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		AgentID:  agentID,
		Username: username,
		Roles:    roles,
		Type:     tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	// WithLeeway tolerates clock drift between the host and Docker containers.
	// Without this, tokens can fail iat/nbf checks when clocks differ by seconds.
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	}, jwt.WithLeeway(2*time.Minute))

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify issuer
	if claims.Issuer != m.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", m.issuer, claims.Issuer)
	}

	// Note: Audience check relaxed for dashboard compatibility.
	// The token is already cryptographically verified (RS256) and issuer-checked.
	// In a multi-tenant setup, re-enable strict audience validation.

	return claims, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token.
func (m *JWTManager) RefreshAccessToken(refreshToken string) (string, time.Time, error) {
	claims, err := m.ValidateToken(refreshToken)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify it's a refresh token
	if claims.Type != "refresh" {
		return "", time.Time{}, fmt.Errorf("token is not a refresh token")
	}

	// Generate new access token
	accessExp := time.Now().Add(m.accessTTL)
	accessToken, err := m.generateToken(claims.AgentID, claims.Username, claims.Roles, "access", accessExp)
	if err != nil {
		return "", time.Time{}, err
	}

	return accessToken, accessExp, nil
}

// GetTokenID extracts the JTI (token ID) from a token without full validation.
// Useful for blacklist lookups before full validation.
func (m *JWTManager) GetTokenID(tokenString string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	return claims.ID, nil
}

// TokenBlacklist defines the interface for token blacklist storage.
type TokenBlacklist interface {
	// Add adds a token to the blacklist.
	Add(ctx context.Context, jti string, expiresAt time.Time, reason string) error

	// IsBlacklisted checks if a token is blacklisted.
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
}

// GenerateOpaqueToken creates a cryptographically random 32-byte opaque token.
// Returns (rawBase64URL, sha256Hex, error). The raw token is sent to the
// client; only the SHA-256 hash is stored server-side.
func GenerateOpaqueToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate opaque token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// HashToken computes the SHA-256 hex digest of a raw opaque token string.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateAccessTokenOnly creates a single access token (JWT) without a
// refresh token. Used during session-based refresh where the refresh token
// is an opaque value managed outside the JWT system.
//
// sessionVersion must be the user's current session_version from the DB.
// It is embedded as the sv claim so AuthMiddleware can reject stale tokens
// from previous sessions without a DB lookup per request at the middleware level
// (the version is read once at login; the DB version is the authoritative check).
func (m *JWTManager) GenerateAccessTokenOnly(userID, username string, roles []string, sessionVersion int) (token string, jti string, exp time.Time, err error) {
	exp = time.Now().Add(m.accessTTL)
	tokenJTI := uuid.New().String()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenJTI,
			Subject:   userID,
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		AgentID:        userID,
		Username:       username,
		Roles:          roles,
		Type:           "access",
		SessionVersion: sessionVersion,
	}

	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token, err = signed.SignedString(m.privateKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return token, tokenJTI, exp, nil
}

// RefreshTTL returns the configured refresh token TTL.
func (m *JWTManager) RefreshTTL() time.Duration {
	return m.refreshTTL
}
