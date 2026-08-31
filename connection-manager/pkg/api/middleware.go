// Package api provides middleware implementations.
package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/audit"
	"github.com/edr-platform/connection-manager/pkg/handlers"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// Handlers contains all API handler methods.
type Handlers struct {
	logger              *logrus.Logger
	jwtManager          *security.JWTManager
	redis               *cache.RedisClient
	rateLimiter         *cache.RateLimiter
	agentSvc            service.AgentService                   // optional: nil when DB unavailable
	authSvc             service.AuthService                    // optional: nil when DB unavailable
	caCertPath          string                                 // path to CA certificate for zero-touch provisioning
	enrollmentTokenRepo repository.EnrollmentTokenRepository   // optional: nil when DB unavailable
	registry            *handlers.AgentRegistry                // real-time agent command routing
	commandRepo         repository.CommandRepository           // C2 command persistence
	quarantineRepo      repository.QuarantineRepository        // optional quarantine inventory
	auditRepo           repository.AuditLogRepository          // audit log querying
	alertRepo           repository.AlertRepository             // alert querying and stats
	eventRepo           repository.EventRepository             // event search/list (durable store)
	forensicRepo        repository.ForensicRepository          // forensic collections/events (collect_logs)
	agentPackageRepo    repository.AgentPackageRepository      // built agent packages for patch/upgrade
	agentPatchRepo      repository.AgentPatchProfileRepository // per-agent patch profile (UI prefill)
	userRepo            repository.UserRepository              // user CRUD
	roleRepo            repository.RoleRepository              // RBAC role/permission management
	contextPolicyRepo   repository.ContextPolicyRepository     // context-aware policy controls
	grpcAddress         string                                 // C2 gRPC address (host:port) injected into isolate params
	fallbackStore       *handlers.EventFallbackStore           // DB fallback store reliability stats
	incidentRepo        repository.IncidentRepository          // post-isolation playbook + triage tracking
	vulnRepo            repository.VulnerabilityRepository     // CVE / software vulnerability findings per agent
	kevSync             *service.KEVSyncService                // CISA KEV synchronization service
	vulnScannerIngest   *service.VulnScannerIngestService      // Trivy/Grype report parser
	siemRepo            repository.SiemConnectorRepository     // SIEM / webhook export destinations
	AutomationHandlers  *AutomationHandlers                    // automation handlers for intelligent response
	malwareHashRepo     repository.MalwareHashRepository       // server-managed malicious hash feed
	signatureSyncSvc    *service.SignatureSyncService          // background MalwareBazaar sync
	commandApprovalSvc  service.CommandApprovalService         // optional: out-of-band OTP gate for manual commands
	sessionRepo         repository.SessionRepository           // session tracking for refresh token rotation
	securityEventRepo   *audit.Repository                     // security audit event queries
	auditLogger         *audit.Logger                         // non-blocking security event writer
}

// NewHandlers creates a new handlers instance.
func NewHandlers(
	logger *logrus.Logger,
	jwtManager *security.JWTManager,
	redis *cache.RedisClient,
	ratLimiter *cache.RateLimiter,
	agentSvc service.AgentService,
	authSvc service.AuthService,
	caCertPath string,
	enrollmentTokenRepo repository.EnrollmentTokenRepository,
	automationHandlers *AutomationHandlers,
) *Handlers {
	return &Handlers{
		logger:              logger,
		jwtManager:          jwtManager,
		redis:               redis,
		rateLimiter:         ratLimiter,
		agentSvc:            agentSvc,
		authSvc:             authSvc,
		caCertPath:          caCertPath,
		enrollmentTokenRepo: enrollmentTokenRepo,
		AutomationHandlers:  automationHandlers,
	}
}

// SetGRPCAddress sets the C2 gRPC server address (host:port).
// When set, it is automatically injected as "server_address" into isolate_network
// and unisolate_network command parameters so the agent knows which IP/port to
// allow through the firewall without requiring the dashboard to pass it.
func (h *Handlers) SetGRPCAddress(addr string) {
	h.grpcAddress = addr
}

// SetRegistry sets the AgentRegistry for command routing.
func (h *Handlers) SetRegistry(r *handlers.AgentRegistry) {
	h.registry = r
}

// SetAuditRepo sets the AuditLogRepository for audit log querying.
func (h *Handlers) SetAuditRepo(repo repository.AuditLogRepository) {
	h.auditRepo = repo
}

// SetAlertRepo sets the AlertRepository for alert querying and stats.
func (h *Handlers) SetAlertRepo(repo repository.AlertRepository) {
	h.alertRepo = repo
}

// SetEventRepo sets the EventRepository for event search/list.
func (h *Handlers) SetEventRepo(repo repository.EventRepository) {
	h.eventRepo = repo
}

// SetCommandRepo sets the CommandRepository for C2 persistence.
func (h *Handlers) SetCommandRepo(repo repository.CommandRepository) {
	h.commandRepo = repo
}

// SetQuarantineRepo sets the quarantine inventory repository.
func (h *Handlers) SetQuarantineRepo(repo repository.QuarantineRepository) {
	h.quarantineRepo = repo
}

// SetForensicRepo sets the ForensicRepository for forensic log browsing.
func (h *Handlers) SetForensicRepo(repo repository.ForensicRepository) {
	h.forensicRepo = repo
}

func (h *Handlers) SetAgentPackageRepo(repo repository.AgentPackageRepository) {
	h.agentPackageRepo = repo
}

func (h *Handlers) SetAgentPatchProfileRepo(repo repository.AgentPatchProfileRepository) {
	h.agentPatchRepo = repo
}

// SetUserRepo sets the UserRepository for user CRUD operations.
func (h *Handlers) SetUserRepo(repo repository.UserRepository) {
	h.userRepo = repo
}

// SetRoleRepo sets the RoleRepository for RBAC role/permission management.
func (h *Handlers) SetRoleRepo(repo repository.RoleRepository) {
	h.roleRepo = repo
}

// SetContextPolicyRepo sets the ContextPolicyRepository for context-aware controls.
func (h *Handlers) SetContextPolicyRepo(repo repository.ContextPolicyRepository) {
	h.contextPolicyRepo = repo
}

// SetFallbackStore sets the EventFallbackStore for reliability health.
func (h *Handlers) SetFallbackStore(store *handlers.EventFallbackStore) {
	h.fallbackStore = store
}

// SetIncidentRepo sets the IncidentRepository for post-isolation tracking.
func (h *Handlers) SetIncidentRepo(repo repository.IncidentRepository) {
	h.incidentRepo = repo
}

// SetVulnRepo sets the VulnerabilityRepository for SOC vulnerability findings.
func (h *Handlers) SetVulnRepo(repo repository.VulnerabilityRepository) {
	h.vulnRepo = repo
}

// SetKEVSync wires the CISA KEV synchronization service for manual triggers.
func (h *Handlers) SetKEVSync(svc *service.KEVSyncService) {
	h.kevSync = svc
}

// SetVulnScannerIngest wires the scanner parser service (Trivy/Grype).
func (h *Handlers) SetVulnScannerIngest(svc *service.VulnScannerIngestService) {
	h.vulnScannerIngest = svc
}

// SetSiemRepo sets the SiemConnectorRepository for SIEM export configuration.
func (h *Handlers) SetSiemRepo(repo repository.SiemConnectorRepository) {
	h.siemRepo = repo
}

// SetMalwareHashRepo wires the server-managed hash feed repository.
func (h *Handlers) SetMalwareHashRepo(repo repository.MalwareHashRepository) {
	h.malwareHashRepo = repo
}

// SetSignatureSyncSvc wires the background MalwareBazaar sync service.
func (h *Handlers) SetSignatureSyncSvc(svc *service.SignatureSyncService) {
	h.signatureSyncSvc = svc
}

// SetSessionRepo sets the SessionRepository for refresh token rotation.
func (h *Handlers) SetSessionRepo(repo repository.SessionRepository) {
	h.sessionRepo = repo
}

// SetSecurityEventRepo sets the audit.Repository for security event queries.
func (h *Handlers) SetSecurityEventRepo(repo *audit.Repository) {
	h.securityEventRepo = repo
}

// SetAuditLogger wires the non-blocking security event logger.
func (h *Handlers) SetAuditLogger(l *audit.Logger) {
	h.auditLogger = l
}

// UserClaims represents authenticated user info.
type UserClaims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

// ContextKey for context values.
type ContextKey string

const (
	ContextKeyUser ContextKey = "user"
)

// AuthMiddleware validates JWT tokens.
func (h *Handlers) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if h.jwtManager == nil {
			return errorResponse(c, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "JWT authentication is not configured")
		}

		// Extract token from header
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return errorResponse(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authorization header is required")
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return errorResponse(c, http.StatusUnauthorized, "INVALID_AUTH_FORMAT", "Authorization header must be 'Bearer {token}'")
		}

		token := parts[1]

		// Check if token is blacklisted (by JTI, not raw token string)
		if h.redis != nil && h.jwtManager != nil {
			if jti, err := h.jwtManager.GetTokenID(token); err == nil && jti != "" {
				blacklisted, err := h.redis.IsTokenBlacklisted(c.Request().Context(), jti)
				if err != nil {
					h.logger.WithError(err).Warn("Failed to check token blacklist")
				} else if blacklisted {
					return errorResponse(c, http.StatusUnauthorized, "TOKEN_REVOKED", "Token has been revoked")
				}
			}
		}

		// Validate token
		claims, err := h.jwtManager.ValidateToken(token)
		if err != nil {
			h.logger.WithError(err).WithField("path", c.Request().URL.Path).Warn("JWT validation failed")
			return errorResponse(c, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
		}

		// ── Session Version check ─────────────────────────────────────────────
		// If the token carries an sv claim (session_version > 0) and userRepo is
		// available, verify it matches the current DB value. A mismatch means the
		// user logged in (or out) from another browser/device, incrementing the DB
		// counter, so this token is now stale and must be rejected immediately.
		//
		// Tokens with sv == 0 (legacy tokens or agent tokens without the claim)
		// skip this check to preserve backward compatibility.
		if claims.SessionVersion > 0 && h.userRepo != nil {
			if uid, parseErr := uuid.Parse(claims.Subject); parseErr == nil {
				dbVersion, svErr := h.userRepo.GetSessionVersion(c.Request().Context(), uid)
				if svErr != nil {
					// DB unavailable — fail open (log and continue) so a DB blip
					// doesn't log everyone out.
					h.logger.WithError(svErr).Warn("session_version DB check failed — skipping sv enforcement")
				} else if dbVersion != claims.SessionVersion {
					h.logger.WithFields(map[string]interface{}{
						"user_id":    claims.Subject,
						"token_sv":   claims.SessionVersion,
						"db_sv":      dbVersion,
						"path":       c.Request().URL.Path,
					}).Warn("Session invalidated: sv mismatch (new login or logout from another device)")
					return errorResponse(c, http.StatusUnauthorized, "SESSION_INVALIDATED",
						"A new login has invalidated this session. Please log in again.")
				}
			}
		}

		// Extract user claims — Username is the human-readable login name now
		// embedded in the token. Subject is still the user UUID.
		user := &UserClaims{
			UserID:   claims.Subject,
			Username: claims.Username,
			Roles:    claims.Roles,
		}

		// Store user in context
		c.Set(string(ContextKeyUser), user)

		return next(c)
	}
}


// RequireRole checks if user has required role.
func (h *Handlers) RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get(string(ContextKeyUser)).(*UserClaims)
			if !ok || user == nil {
				return errorResponse(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
			}

			// Check if user has any of the required roles
			for _, requiredRole := range roles {
				for _, userRole := range user.Roles {
					if userRole == requiredRole || userRole == "admin" {
						return next(c)
					}
				}
			}

			return errorResponse(c, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions")
		}
	}
}

// RequirePermission checks if the authenticated user's role(s) grant
// the specified resource:action permission. Falls back to admin bypass.
func (h *Handlers) RequirePermission(resource, action string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get(string(ContextKeyUser)).(*UserClaims)
			if !ok || user == nil {
				return errorResponse(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
			}

			// Admin bypass — admins always have full access
			for _, role := range user.Roles {
				if role == "admin" {
					return next(c)
				}
			}

			// Check permission via DB lookup
			if h.roleRepo != nil {
				permKey := resource + ":" + action
				for _, role := range user.Roles {
					perms, err := h.roleRepo.GetPermissionsForRoleName(c.Request().Context(), role)
					if err != nil {
						h.logger.WithError(err).Warnf("Failed to get permissions for role %s", role)
						continue
					}
					for _, p := range perms {
						if p == permKey {
							return next(c)
						}
					}
				}
			}

			return errorResponse(c, http.StatusForbidden, "FORBIDDEN",
				fmt.Sprintf("Missing permission: %s:%s", resource, action))
		}
	}
}

// RateLimitMiddleware applies rate limiting per user.
func (h *Handlers) RateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if h.rateLimiter == nil {
			return next(c)
		}

		// Get user ID or IP for rate limiting
		var key string
		if user, ok := c.Get(string(ContextKeyUser)).(*UserClaims); ok && user != nil {
			key = user.UserID
		} else {
			key = c.RealIP()
		}

		// Allow(ctx, agentID, eventCount) returns (bool, int64, error)
		allowed, _, err := h.rateLimiter.Allow(c.Request().Context(), key, 1)
		if err != nil {
			h.logger.WithError(err).Warn("Rate limit check failed")
			// Continue on error
			return next(c)
		}

		if !allowed {
			return errorResponse(c, http.StatusTooManyRequests, "RATE_LIMITED", "Rate limit exceeded")
		}

		return next(c)
	}
}

// getCurrentUser extracts user claims from Echo context (set by AuthMiddleware).
func getCurrentUser(c echo.Context) *UserClaims {
	user, _ := c.Get(string(ContextKeyUser)).(*UserClaims)
	return user
}

// getClientIP extracts the real client IP address considering that the backend
// sits behind a Dockerized Nginx reverse proxy which sets X-Forwarded-For.
//
// Resolution order:
//  1. First non-private IP in X-Forwarded-For (spoofing-safe: leftmost is client)
//  2. X-Real-IP header
//  3. Echo's built-in RealIP (strips port)
//  4. Raw RemoteAddr as final fallback
func getClientIP(c echo.Context) string {
	// Parse X-Forwarded-For — may contain multiple IPs: "client, proxy1, proxy2"
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			ip := strings.TrimSpace(part)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// X-Real-IP (set by Nginx proxy_set_header X-Real-IP $remote_addr)
	if xri := c.Request().Header.Get("X-Real-IP"); xri != "" {
		xri = strings.TrimSpace(xri)
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Echo built-in — strips port from RemoteAddr automatically
	if ip := c.RealIP(); ip != "" {
		return ip
	}

	// Last resort: strip port manually from RemoteAddr
	addr := c.Request().RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// auditContext returns (ipAddress, userAgent) for AuditLog.WithContext calls.
func auditContext(c echo.Context) (string, string) {
	return getClientIP(c), c.Request().Header.Get("User-Agent")
}

// errorResponse returns a standardized error response.
func errorResponse(c echo.Context, status int, code, message string) error {
	return c.JSON(status, ErrorResponse{
		Error:     http.StatusText(status),
		ErrorCode: code,
		Message:   message,
		RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// successResponse returns a standardized success response.
func successResponse(c echo.Context, status int, data interface{}) error {
	return c.JSON(status, data)
}

// Sync
