// Package server provides middleware interceptors for the gRPC server.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/edr-platform/connection-manager/config"
	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/audit"
	"github.com/edr-platform/connection-manager/pkg/contextkeys"
	"github.com/edr-platform/connection-manager/pkg/security"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// Context keys for request data.
type contextKey string

const (
	ContextKeyRequestID contextKey = "request_id"
	ContextKeyTraceID   contextKey = "trace_id"
	ContextKeyUserID    contextKey = "user_id"
	ContextKeyCert      contextKey = "client_cert"
)

// Interceptor provides middleware functionality for gRPC requests.
type Interceptor struct {
	cfg         *config.Config
	logger      *logrus.Logger
	redis       *cache.RedisClient
	jwtManager  *security.JWTManager
	rateLimiter *cache.RateLimiter
	crlCache    *repository.CRLCache // DB-backed in-memory CRL (optional)
	auditLogger *audit.Logger        // non-blocking security event logger (nil-safe)

	// Local cert revocation cache — synced from Redis periodically.
	// When Redis is down, this cache enables fail-closed behavior:
	// if the cache is stale (> revocationCacheMaxAge), reject connections.
	revokedCerts     sync.Map   // fingerprint → struct{}
	lastCacheSync    atomic.Int64 // unix timestamp of last successful Redis sync
}

const revocationCacheMaxAge = 5 * time.Minute // max staleness before fail-closed

// NewInterceptor creates a new interceptor and starts the revocation cache sync loop.
func NewInterceptor(cfg *config.Config, logger *logrus.Logger, redis *cache.RedisClient, jwtManager *security.JWTManager) *Interceptor {
	i := &Interceptor{
		cfg:         cfg,
		logger:      logger,
		redis:       redis,
		jwtManager:  jwtManager,
		rateLimiter: cache.NewRateLimiter(redis, cfg.RateLimit.EventsPerSecond, cfg.RateLimit.BurstMultiplier),
	}
	// Seed the timestamp so we don't immediately fail-closed on boot.
	i.lastCacheSync.Store(time.Now().Unix())
	return i
}

// SetCRLCache injects the DB-backed CRL cache for fingerprint revocation checks.
func (i *Interceptor) SetCRLCache(cache *repository.CRLCache) {
	i.crlCache = cache
}

// SetAuditLogger wires the non-blocking security event logger.
func (i *Interceptor) SetAuditLogger(l *audit.Logger) {
	i.auditLogger = l
}

// ============================================================================
// LOGGING INTERCEPTORS
// ============================================================================

// LoggingUnaryInterceptor logs all unary RPC calls.
func (i *Interceptor) LoggingUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()
	requestID := generateRequestID(ctx)
	ctx = context.WithValue(ctx, ContextKeyRequestID, requestID)

	// Debug: log as soon as the request reaches the server (helps diagnose handshake/connection aborts)
	if p, ok := peer.FromContext(ctx); ok && p != nil && p.Addr != nil {
		i.logger.WithFields(logrus.Fields{
			"method":      info.FullMethod,
			"remote_addr": p.Addr.String(),
			"request_id":  requestID,
		}).Debug("gRPC unary request reached server")
	} else {
		i.logger.WithFields(logrus.Fields{"method": info.FullMethod, "request_id": requestID}).Debug("gRPC unary request reached server (no peer)")
	}

	// Extract agent ID from context if available
	agentID := extractAgentIDFromContext(ctx)

	// Call handler
	resp, err := handler(ctx, req)

	// Calculate latency
	latency := time.Since(start)

	// Log request
	fields := logrus.Fields{
		"method":     info.FullMethod,
		"request_id": requestID,
		"latency_ms": latency.Milliseconds(),
	}

	if agentID != "" {
		fields["agent_id"] = agentID
	}

	if err != nil {
		st, _ := status.FromError(err)
		fields["status"] = st.Code().String()
		fields["error"] = st.Message()
		i.logger.WithFields(fields).Warn("gRPC request failed")
	} else {
		fields["status"] = "OK"
		i.logger.WithFields(fields).Info("gRPC request completed")
	}

	return resp, err
}

// LoggingStreamInterceptor logs all streaming RPC calls.
func (i *Interceptor) LoggingStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	start := time.Now()
	ctx := ss.Context()
	requestID := generateRequestID(ctx)

	// Debug: log as soon as the stream reaches the server (helps diagnose handshake/connection aborts)
	if p, ok := peer.FromContext(ctx); ok && p != nil && p.Addr != nil {
		i.logger.WithFields(logrus.Fields{
			"method":      info.FullMethod,
			"remote_addr": p.Addr.String(),
			"request_id":  requestID,
		}).Debug("gRPC stream request reached server")
	} else {
		i.logger.WithFields(logrus.Fields{"method": info.FullMethod, "request_id": requestID}).Debug("gRPC stream request reached server (no peer)")
	}

	agentID := extractAgentIDFromContext(ctx)

	// Wrap stream with context
	wrapped := &wrappedServerStream{ServerStream: ss, ctx: context.WithValue(ctx, ContextKeyRequestID, requestID)}

	// Call handler
	err := handler(srv, wrapped)

	// Calculate duration
	duration := time.Since(start)

	fields := logrus.Fields{
		"method":      info.FullMethod,
		"request_id":  requestID,
		"duration_ms": duration.Milliseconds(),
	}

	if agentID != "" {
		fields["agent_id"] = agentID
	}

	if err != nil {
		st, _ := status.FromError(err)
		fields["status"] = st.Code().String()
		fields["error"] = st.Message()
		i.logger.WithFields(fields).Warn("gRPC stream closed with error")
	} else {
		fields["status"] = "OK"
		i.logger.WithFields(fields).Info("gRPC stream closed")
	}

	return err
}

// ============================================================================
// AUTHENTICATION INTERCEPTORS
// ============================================================================

// AuthUnaryInterceptor validates mTLS certificates and JWT tokens.
// RegisterAgent is allowed without a client certificate (bootstrap flow): the handler
// validates the InstallationToken from the request body against the database.
// All other RPCs require a valid, verified client certificate (and JWT when configured).
func (i *Interceptor) AuthUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if info.FullMethod == "/edr.v1.EventIngestionService/RegisterAgent" {
		// Bootstrap flow: no client cert required. Require non-empty token in request so we
		// don't allow anonymous registration attempts; handler validates token against DB.
		if reg, ok := req.(*edrv1.AgentRegistrationRequest); ok && reg != nil && reg.InstallationToken != "" {
			return handler(ctx, req)
		}
		// RegisterAgent with empty token: reject at interceptor
		if _, ok := req.(*edrv1.AgentRegistrationRequest); ok {
			return nil, status.Error(codes.Unauthenticated, "RegisterAgent requires non-empty installation token")
		}
		return handler(ctx, req)
	}

	// All other RPCs: require valid client certificate (mTLS)
	agentID, err := i.validateClientCertificate(ctx)
	if err != nil {
		i.logger.WithError(err).Warn("Certificate validation failed")
		return nil, status.Errorf(codes.Unauthenticated, "certificate validation failed: %v", err)
	}

	ctx = context.WithValue(ctx, contextkeys.AgentIDKey, agentID)

	// Agent-to-server unary RPCs authenticate via mTLS certificate only.
	// JWT tokens are only required for REST API calls, not agent gRPC calls.
	// These methods are called directly by agents using conn.Invoke() with no JWT.
	switch info.FullMethod {
	case "/edr.v1.EventIngestionService/SendCommandResult",
		"/edr.v1.EventIngestionService/Heartbeat",
		"/edr.v1.EventIngestionService/RequestCertificateRenewal":
		return handler(ctx, req)
	}

	// Validate JWT token (if JWTManager is configured) — for non-agent RPCs
	if i.jwtManager != nil {
		token := extractTokenFromMetadata(ctx)
		if token == "" {
			i.logger.WithField("agent_id", agentID).Warn("No JWT token provided")
			return nil, status.Errorf(codes.Unauthenticated, "missing authentication token")
		}

		claims, err := i.jwtManager.ValidateToken(token)
		if err != nil {
			i.logger.WithError(err).WithField("agent_id", agentID).Warn("JWT validation failed")
			return nil, status.Errorf(codes.Unauthenticated, "token validation failed: %v", err)
		}

		// Cross-check: token's agent_id must match the certificate's agent_id
		if claims.AgentID != agentID {
			i.logger.WithFields(logrus.Fields{
				"cert_agent_id":  agentID,
				"token_agent_id": claims.AgentID,
			}).Warn("Agent ID mismatch between certificate and token")
			return nil, status.Errorf(codes.Unauthenticated, "agent ID mismatch")
		}
	}

	return handler(ctx, req)
}

// AuthStreamInterceptor validates mTLS certificates for streaming RPCs.
func (i *Interceptor) AuthStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	ctx := ss.Context()

	// Validate client certificate
	agentID, err := i.validateClientCertificate(ctx)
	if err != nil {
		i.logger.WithError(err).Warn("Certificate validation failed")
		return status.Errorf(codes.Unauthenticated, "certificate validation failed: %v", err)
	}

	// Wrap stream with authenticated context
	newCtx := context.WithValue(ctx, contextkeys.AgentIDKey, agentID)
	wrapped := &wrappedServerStream{ServerStream: ss, ctx: newCtx}

	return handler(srv, wrapped)
}

// validateClientCertificate extracts and validates the client certificate.
// Cert revocation uses a layered approach:
//  1. If Redis is available: check Redis and update local cache.
//  2. If Redis is down but local cache is fresh (< 5 min): use local cache.
//  3. If Redis is down AND cache is stale (> 5 min): FAIL-CLOSED — reject.
func (i *Interceptor) validateClientCertificate(ctx context.Context) (string, error) {
	// Get peer info from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer info")
	}

	// Get TLS info
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no TLS info")
	}

	// Get client certificate
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "no verified certificate chain")
	}

	clientCert := tlsInfo.State.VerifiedChains[0][0]

	// Extract agent ID from certificate
	agentID, err := extractAgentIDFromCert(clientCert)
	if err != nil {
		return "", err
	}

	// ── Certificate Revocation Check (fail-closed) ──
	fingerprint := generateFingerprint(clientCert.Raw)

	// Layer 1: DB-backed in-memory CRL cache (never hits DB, cache-only)
	if i.crlCache != nil && i.crlCache.IsRevoked(fingerprint) {
		// Extract peer address for audit (best-effort).
		remoteAddr := ""
		if p, ok := peer.FromContext(ctx); ok && p != nil && p.Addr != nil {
			remoteAddr = p.Addr.String()
		}
		i.auditLogger.CertRejectedCRL(fingerprint, agentID, remoteAddr)
		return "", status.Error(codes.PermissionDenied, "certificate revoked")
	}

	// Layer 2: Redis-backed revocation check (existing mechanism)
	if i.redis != nil {
		// Redis is configured — try live check
		revoked, err := i.redis.IsCertRevoked(ctx, fingerprint)
		if err != nil {
			// Redis error — fall through to local cache check below
			i.logger.WithError(err).Warn("Redis cert revocation check failed — falling back to local cache")
		} else {
			// Redis responded successfully — update local cache and timestamp
			i.lastCacheSync.Store(time.Now().Unix())
			if revoked {
				i.revokedCerts.Store(fingerprint, struct{}{})
				return "", status.Error(codes.Unauthenticated, "certificate revoked")
			}
			// Not revoked — ensure it's not in local cache either
			i.revokedCerts.Delete(fingerprint)
			// Record last_seen_at asynchronously — never block gRPC call
			if i.crlCache != nil {
				go i.crlCache.RecordLastSeen(fingerprint)
			}
			return agentID, nil
		}
	}

	// Redis unavailable (nil or errored) — consult local cache
	if _, revoked := i.revokedCerts.Load(fingerprint); revoked {
		return "", status.Error(codes.Unauthenticated, "certificate revoked (cached)")
	}

	// Check cache staleness — if too old, fail-closed for security
	lastSync := time.Unix(i.lastCacheSync.Load(), 0)
	if time.Since(lastSync) > revocationCacheMaxAge {
		i.logger.WithFields(logrus.Fields{
			"agent_id":        agentID,
			"cache_age":       time.Since(lastSync).Round(time.Second).String(),
			"max_cache_age":   revocationCacheMaxAge.String(),
		}).Warn("Cert revocation cache stale and Redis unavailable — REJECTING connection (fail-closed)")
		return "", status.Error(codes.Unauthenticated, "certificate revocation check unavailable — try again later")
	}

	// Record last_seen_at asynchronously — never block gRPC call
	if i.crlCache != nil {
		go i.crlCache.RecordLastSeen(fingerprint)
	}

	// Cache is fresh enough — allow connection
	return agentID, nil
}

// AddToRevocationCache adds a fingerprint to the local revocation cache.
// Called externally when a cert is revoked via the REST API so the cache
// is updated immediately without waiting for the next Redis sync.
func (i *Interceptor) AddToRevocationCache(fingerprint string) {
	i.revokedCerts.Store(fingerprint, struct{}{})
}

// ============================================================================
// RATE LIMITING INTERCEPTOR
// ============================================================================

// RateLimitUnaryInterceptor applies rate limiting to unary requests.
func (i *Interceptor) RateLimitUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if !i.cfg.RateLimit.Enabled {
		return handler(ctx, req)
	}

	agentID := extractAgentIDFromContext(ctx)
	if agentID == "" {
		return handler(ctx, req)
	}

	allowed, count, err := i.rateLimiter.Allow(ctx, agentID, 1)
	if err != nil {
		i.logger.WithError(err).Warn("Rate limiter error")
		// Continue on error (fail-open)
		return handler(ctx, req)
	}

	if !allowed {
		i.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"count":    count,
			"limit":    i.cfg.RateLimit.EventsPerSecond,
		}).Warn("Rate limit exceeded")

		return nil, status.Errorf(codes.ResourceExhausted,
			"rate limit exceeded: %d requests/sec (limit: %d)",
			count, i.cfg.RateLimit.EventsPerSecond)
	}

	return handler(ctx, req)
}

// RateLimitStreamInterceptor applies rate limiting to streaming RPCs.
// Checks the per-agent event budget at stream establishment time.
func (i *Interceptor) RateLimitStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if !i.cfg.RateLimit.Enabled {
		return handler(srv, ss)
	}

	ctx := ss.Context()
	agentID := extractAgentIDFromContext(ctx)
	if agentID == "" {
		return handler(srv, ss)
	}

	allowed, count, err := i.rateLimiter.Allow(ctx, agentID, 1)
	if err != nil {
		i.logger.WithError(err).Warn("Rate limiter error on stream open")
		return handler(srv, ss)
	}

	if !allowed {
		i.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"count":    count,
			"limit":    i.cfg.RateLimit.EventsPerSecond,
			"method":   info.FullMethod,
		}).Warn("Stream rate limit exceeded")

		return status.Errorf(codes.ResourceExhausted,
			"stream rate limit exceeded for agent %s: %d requests/sec (limit: %d)",
			agentID, count, i.cfg.RateLimit.EventsPerSecond)
	}

	return handler(srv, ss)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// wrappedServerStream wraps grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// generateRequestID generates a unique request ID.
func generateRequestID(ctx context.Context) string {
	// Try to get from metadata first
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ids := md.Get("x-request-id"); len(ids) > 0 {
			return ids[0]
		}
	}
	return uuid.New().String()
}

// extractAgentIDFromContext extracts the agent ID from context.
func extractAgentIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextkeys.AgentIDKey).(string); ok {
		return id
	}
	return ""
}

// extractTokenFromMetadata extracts the Bearer token from gRPC metadata.
func extractTokenFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}

	// Expect "Bearer <token>" format
	auth := values[0]
	const bearerPrefix = "Bearer "
	if len(auth) > len(bearerPrefix) && auth[:len(bearerPrefix)] == bearerPrefix {
		return auth[len(bearerPrefix):]
	}

	return ""
}

// extractAgentIDFromCert extracts the agent ID from certificate.
func extractAgentIDFromCert(cert *x509.Certificate) (string, error) {
	// Check DNS names first
	for _, dnsName := range cert.DNSNames {
		if len(dnsName) > 6 && dnsName[:6] == "agent-" {
			return dnsName[6:], nil
		}
	}

	// Check URI SANs
	for _, uri := range cert.URIs {
		if uri.Scheme == "urn" && uri.Opaque != "" {
			if len(uri.Opaque) > 10 && uri.Opaque[:10] == "edr:agent:" {
				return uri.Opaque[10:], nil
			}
		}
	}

	// Fallback to Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}

	return "", status.Error(codes.Unauthenticated, "agent ID not found in certificate")
}

// generateFingerprint generates SHA256 fingerprint of certificate DER bytes.
func generateFingerprint(certBytes []byte) string {
	hash := sha256.Sum256(certBytes)
	return hex.EncodeToString(hash[:])
}
