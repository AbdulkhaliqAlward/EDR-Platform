// Package handlers provides security middleware for the API.
package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/golang-jwt/jwt/v5"
)

// RateLimiter limits request rates per IP.
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*bucket
	rate     int           // Max requests per window
	window   time.Duration // Time window
}

type bucket struct {
	count     int
	lastReset time.Time
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*bucket),
		rate:     rate,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

// Allow checks if request is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.requests[ip]

	if !exists || now.Sub(b.lastReset) > rl.window {
		rl.requests[ip] = &bucket{count: 1, lastReset: now}
		return true
	}

	if b.count >= rl.rate {
		return false
	}

	b.count++
	return true
}

// cleanup removes old entries.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, b := range rl.requests {
			if now.Sub(b.lastReset) > rl.window*2 {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware applies rate limiting.
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)

			if !limiter.Allow(ip) {
				logger.Warnf("Rate limit exceeded for %s", ip)
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// SecurityHeaders adds security headers to responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// HSTS (only for HTTPS)
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds a request ID to context.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// generateRequestID creates a simple request ID.
func generateRequestID() string {
	return time.Now().Format("20060102150405.999999999")
}

// RecoveryMiddleware recovers from panics.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Errorf("Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// TokenAuth validates bearer tokens.
type TokenAuth struct {
	validTokens map[string]bool
	mu          sync.RWMutex
}

// NewTokenAuth creates a token authenticator.
func NewTokenAuth(tokens []string) *TokenAuth {
	auth := &TokenAuth{
		validTokens: make(map[string]bool),
	}
	for _, t := range tokens {
		auth.validTokens[t] = true
	}
	return auth
}

// AddToken adds a valid token.
func (ta *TokenAuth) AddToken(token string) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	ta.validTokens[token] = true
}

// ValidateToken checks if token is valid.
func (ta *TokenAuth) ValidateToken(token string) bool {
	ta.mu.RLock()
	defer ta.mu.RUnlock()
	return ta.validTokens[token]
}

// AuthMiddleware validates API authentication.
func AuthMiddleware(auth *TokenAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
				return
			}

			// Extract bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Unauthorized: invalid format", http.StatusUnauthorized)
				return
			}

			token := parts[1]
			if !auth.ValidateToken(token) {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// RSA JWT Authentication (for Dashboard tokens signed by Connection Manager)
// =============================================================================

// JWTAuth validates RSA-signed JWT tokens using a public key.
// It only needs the public key — it verifies tokens but never signs them.
type JWTAuth struct {
	publicKey *rsa.PublicKey
}

// NewJWTAuth creates a JWT authenticator from an RSA public key PEM file.
func NewJWTAuth(publicKeyPath string) (*JWTAuth, error) {
	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT public key %s: %w", publicKeyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", publicKeyPath)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	logger.Infof("JWT RSA public key loaded from %s", publicKeyPath)
	return &JWTAuth{publicKey: rsaPubKey}, nil
}

// ValidateJWT parses and validates an RS256 JWT token.
// Returns the parsed token if valid.
func (ja *JWTAuth) ValidateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Enforce RS256 signing method to prevent algorithm-switching attacks
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ja.publicKey, nil
	})
	return token, err
}

// CombinedAuthMiddleware tries JWT validation first, then falls back to API key.
// This allows both dashboard users (JWT) and service-to-service calls (API key)
// to authenticate against the Sigma Engine.
//
// Token resolution order:
//  1. Authorization: Bearer <token> header  (REST API, standard)
//  2. ?token=<token> query parameter        (WebSocket — browser WS API cannot set headers)
func CombinedAuthMiddleware(jwtAuth *JWTAuth, tokenAuth *TokenAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Resolve token: Authorization header first, then ?token= query param.
			// The browser WebSocket API (new WebSocket(url)) cannot send custom headers,
			// so the dashboard passes the JWT as a URL query parameter for the WS stream.
			var token string
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
					http.Error(w, "Unauthorized: invalid format", http.StatusUnauthorized)
					return
				}
				token = parts[1]
			} else if q := r.URL.Query().Get("token"); q != "" {
				// WebSocket fallback: accept token from query parameter.
				token = q
			} else {
				http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
				return
			}

			// Strategy 1: Try RSA JWT validation (dashboard tokens)
			if jwtAuth != nil {
				if parsedToken, err := jwtAuth.ValidateJWT(token); err == nil {
					ctx := context.WithValue(r.Context(), ctxAuthKind, "user")
					if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
						if sub, ok := claims["sub"].(string); ok {
							ctx = context.WithValue(ctx, "user_id", sub)
						}
						// Extract username (connection-manager JWT uses "username" key)
						if username, ok := claims["username"].(string); ok {
							ctx = context.WithValue(ctx, "username", username)
						} else if username, ok := claims["preferred_username"].(string); ok {
							ctx = context.WithValue(ctx, "username", username)
						}
						// Extract roles for RBAC enforcement
						if rolesRaw, ok := claims["roles"].([]interface{}); ok {
							roles := make([]string, 0, len(rolesRaw))
							for _, r := range rolesRaw {
								if s, ok := r.(string); ok {
									roles = append(roles, s)
								}
							}
							ctx = context.WithValue(ctx, "user_roles", roles)
						}
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Strategy 2: Fall back to API key validation (service-to-service)
			if tokenAuth != nil && tokenAuth.ValidateToken(token) {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
		})
	}
}
