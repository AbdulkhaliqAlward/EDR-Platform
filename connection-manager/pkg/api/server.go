// Package api provides the REST API server for dashboard integration.
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/config"
	"github.com/edr-platform/connection-manager/pkg/metrics"
)

// Server represents the REST API server.
type Server struct {
	echo    *echo.Echo
	config  *config.APIConfig
	logger  *logrus.Logger
	metrics *metrics.Metrics
}

// NewServer creates a new REST API server.
func NewServer(cfg *config.APIConfig, logger *logrus.Logger, m *metrics.Metrics) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Configure middleware stack
	e.Use(middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: func() string {
			return fmt.Sprintf("req-%d", time.Now().UnixNano())
		},
	}))

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}","id":"${id}","method":"${method}","uri":"${uri}","status":${status},"latency":"${latency_human}","bytes_out":${bytes_out}}` + "\n",
	}))

	e.Use(middleware.Recover())

	// CORS configuration
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     cfg.CORSAllowOrigins,
		AllowMethods:     cfg.CORSAllowMethods,
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
		MaxAge:           3600,
	}))

	// Request timeout (skip for long-running endpoints like agent build)
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Skipper: func(c echo.Context) bool {
			p := c.Request().URL.Path
			return strings.HasSuffix(p, "/agent/build")
		},
		Timeout: cfg.RequestTimeout,
	}))

	// Body limit
	e.Use(middleware.BodyLimit(fmt.Sprintf("%dM", cfg.MaxRequestBodySize/(1024*1024))))

	// Gzip compression
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))

	return &Server{
		echo:    e,
		config:  cfg,
		logger:  logger,
		metrics: m,
	}
}

// RegisterRoutes registers all API routes.
//
// RBAC enforcement: every route has a RequirePermission middleware that checks
// the user's role against the permissions table. This prevents unauthorized
// access even if the dashboard UI hides certain elements — the backend is the
// single source of truth for access control.
func (s *Server) RegisterRoutes(handlers *Handlers) {
	// Health check (no auth)
	s.echo.GET("/healthz", s.healthCheck)
	s.echo.GET("/readyz", s.readyCheck)

	// API v1 group
	v1 := s.echo.Group("/api/v1")

	// Zero-touch provisioning: public CA cert endpoint (no auth required)
	v1.GET("/agent/ca", handlers.ServeCA)
	// Optional public Sysmon config endpoint (no auth required)
	v1.GET("/agent/sysmon/config", handlers.ServeSysmonConfig)


	// Auth endpoints (no auth required for login)
	auth := v1.Group("/auth")
	auth.POST("/login", handlers.Login)
	auth.POST("/login/mfa", handlers.VerifyMFA)
	auth.POST("/refresh", handlers.RefreshToken)
	auth.POST("/logout", handlers.Logout, handlers.AuthMiddleware)
	auth.GET("/me", handlers.GetCurrentUser, handlers.AuthMiddleware)

	// Protected endpoints — all require valid JWT
	protected := v1.Group("")
	protected.Use(handlers.AuthMiddleware)

	// ── Agent/Endpoint endpoints ─────────────────────────────────────────
	// Read: endpoints:read | Modify: endpoints:manage | Isolate: endpoints:isolate
	agents := protected.Group("/agents")
	agents.GET("", handlers.ListAgents, handlers.RequirePermission("endpoints", "read"))
	agents.GET("/stats", handlers.GetAgentStats, handlers.RequirePermission("endpoints", "read"))
	agents.GET("/:id", handlers.GetAgent, handlers.RequirePermission("endpoints", "read"))
	agents.PATCH("/:id", handlers.UpdateAgent, handlers.RequirePermission("endpoints", "manage"))
	agents.PATCH("/:id/business-context", handlers.PatchAgentBusinessContext, handlers.RequirePermission("endpoints", "manage"))
	agents.DELETE("/:id", handlers.DeleteAgent, handlers.RequirePermission("endpoints", "manage"))
	agents.GET("/:id/events", handlers.GetAgentEvents, handlers.RequirePermission("endpoints", "read"))
	agents.GET("/:id/software-inventory", handlers.GetAgentSoftwareInventory, handlers.RequirePermission("endpoints", "read"))
	agents.GET("/:id/quarantine", handlers.ListAgentQuarantine, handlers.RequirePermission("responses", "read"))
	agents.POST("/:id/quarantine/:entryId/decision", handlers.PostAgentQuarantineDecision, handlers.RequirePermission("responses", "execute"))
	agents.GET("/:id/commands", handlers.GetAgentCommands, handlers.RequirePermission("responses", "read"))
	agents.POST("/:id/commands", handlers.ExecuteAgentCommand, handlers.RequirePermission("responses", "execute"))
	agents.POST("/:id/process-exceptions", handlers.AddProcessException, handlers.RequirePermission("responses", "execute"))
	agents.POST("/:id/uninstall-token", handlers.GenerateUninstallToken, handlers.RequirePermission("endpoints", "manage"))
	// Backward-compat alias: some clients may omit the trailing 's'
	agents.POST("/:id/command", handlers.ExecuteAgentCommand, handlers.RequirePermission("responses", "execute"))
	agents.GET("/:id/forensic-collections", handlers.ListForensicCollections, handlers.RequirePermission("responses", "read"))
	agents.GET("/:id/forensic-collections/:commandId/events", handlers.ListForensicEvents, handlers.RequirePermission("responses", "read"))

	// ── Post-isolation incident endpoints ────────────────────────────────
	agents.GET("/:id/incident", handlers.GetIncidentSummary, handlers.RequirePermission("responses", "read"))
	agents.GET("/:id/playbook-runs", handlers.ListPlaybookRuns, handlers.RequirePermission("responses", "read"))
	agents.POST("/:id/collect-memory", handlers.CollectMemoryDump, handlers.RequirePermission("responses", "execute"))
	agents.GET("/:id/iocs", handlers.ListIocEnrichment, handlers.RequirePermission("responses", "read"))
	agents.GET("/:id/triage-snapshots", handlers.ListTriageSnapshots, handlers.RequirePermission("responses", "read"))
	agents.GET("/:id/post-isolation-alerts", handlers.ListPostIsolationAlerts, handlers.RequirePermission("alerts", "read"))
	agents.POST("/:id/incident/false-positive", handlers.MarkIncidentFalsePositive, handlers.RequirePermission("responses", "execute"))
	agents.POST("/:id/incident/escalate", handlers.EscalateIncident, handlers.RequirePermission("responses", "execute"))

	// ── Playbook run detail ───────────────────────────────────────────────
	protected.GET("/playbook-runs/:runId", handlers.GetPlaybookRun, handlers.RequirePermission("responses", "read"))

	// ── Command history endpoints (Action Center) ────────────────────────
	commands := protected.Group("/commands")
	commands.GET("", handlers.ListCommands, handlers.RequirePermission("responses", "read"))
	commands.GET("/stats", handlers.GetCommandStats, handlers.RequirePermission("responses", "read"))
	commands.GET("/capabilities", handlers.GetCommandCapabilities, handlers.RequirePermission("responses", "read"))
	commands.GET("/:id", handlers.GetCommand, handlers.RequirePermission("responses", "read"))

	// ── Out-of-band approval (OTP) for manual commands ───────────────────
	// Both endpoints require the caller to be authenticated AND to hold the
	// "responses:execute" permission — there's no point getting an approval
	// you couldn't redeem anyway. The actual single-use gate is consumed
	// inside ExecuteAgentCommand itself.
	commands.POST("/approval", handlers.IssueCommandApproval, handlers.RequirePermission("responses", "execute"))
	commands.POST("/approval/verify", handlers.VerifyCommandApproval, handlers.RequirePermission("responses", "execute"))

	// ── Response script library ──────────────────────────────────────────
	// Running a script is POST /agents/:id/commands with script_id.
	// Writes additionally require the admin role (enforced in-handler).
	scripts := protected.Group("/response-scripts")
	scripts.GET("", handlers.ListResponseScripts, handlers.RequirePermission("responses", "read"))
	scripts.POST("", handlers.CreateResponseScript, handlers.RequirePermission("responses", "execute"))
	scripts.PUT("/:id", handlers.UpdateResponseScript, handlers.RequirePermission("responses", "execute"))
	scripts.DELETE("/:id", handlers.DeleteResponseScript, handlers.RequirePermission("responses", "execute"))

	// ── Alert endpoints ──────────────────────────────────────────────────
	alerts := protected.Group("/alerts")
	alerts.GET("", handlers.ListAlerts, handlers.RequirePermission("alerts", "read"))
	alerts.POST("/search", handlers.SearchAlerts, handlers.RequirePermission("alerts", "read"))
	alerts.GET("/stats", handlers.GetAlertStats, handlers.RequirePermission("alerts", "read"))
	alerts.GET("/endpoint-risk", handlers.GetEndpointRisk, handlers.RequirePermission("alerts", "read"))
	alerts.GET("/:id", handlers.GetAlert, handlers.RequirePermission("alerts", "read"))
	alerts.PATCH("/:id", handlers.UpdateAlert, handlers.RequirePermission("alerts", "write"))
	alerts.POST("/:id/resolve", handlers.ResolveAlert, handlers.RequirePermission("alerts", "write"))
	alerts.POST("/:id/notes", handlers.AddAlertNote, handlers.RequirePermission("alerts", "write"))
	alerts.DELETE("/:id", handlers.DeleteAlert, handlers.RequirePermission("alerts", "delete"))
	// Automation endpoints for alerts
	if handlers.AutomationHandlers != nil {
		alerts.POST("/:id/execute-playbook", handlers.AutomationHandlers.ExecutePlaybookForAlert, handlers.RequirePermission("alerts", "write"))
		alerts.GET("/:id/suggestions", handlers.AutomationHandlers.GetPlaybookSuggestions, handlers.RequirePermission("alerts", "read"))
		alerts.GET("/:id/executions", handlers.AutomationHandlers.GetPlaybookExecutions, handlers.RequirePermission("alerts", "read"))
	}

	// ── SIEM / external forwarding destinations (not in-app alert or event UIs) ──
	siem := protected.Group("/siem")
	siem.GET("/connectors", handlers.ListSiemConnectors, handlers.RequirePermission("settings", "read"))
	siem.POST("/connectors", handlers.CreateSiemConnector, handlers.RequirePermission("settings", "write"))
	siem.PATCH("/connectors/:id", handlers.PatchSiemConnector, handlers.RequirePermission("settings", "write"))
	siem.DELETE("/connectors/:id", handlers.DeleteSiemConnector, handlers.RequirePermission("settings", "write"))

	// ── Vulnerability findings (CVE/software posture per agent) ─────────
	// Distinct from alerts (detections) and patch KB lists — triage workflow on imported/scanned rows.
	vuln := protected.Group("/vuln")
	vuln.GET("/findings", handlers.ListVulnerabilityFindings, handlers.RequirePermission("endpoints", "read"))
	vuln.GET("/findings/:id", handlers.GetVulnerabilityFinding, handlers.RequirePermission("endpoints", "read"))
	vuln.PATCH("/findings/:id", handlers.PatchVulnerabilityFindingStatus, handlers.RequirePermission("endpoints", "manage"))
	vuln.POST("/findings/bulk", handlers.BulkImportVulnerabilityFindings, handlers.RequirePermission("endpoints", "manage"))
	vuln.POST("/scanners/ingest", handlers.IngestScannerReport, handlers.RequirePermission("endpoints", "manage"))
	vuln.POST("/kev/sync", handlers.SyncKEVCatalog, handlers.RequirePermission("endpoints", "manage"))
	vuln.GET("/stats", handlers.GetVulnerabilityStats, handlers.RequirePermission("endpoints", "read"))

	// ── Event endpoints ──────────────────────────────────────────────────
	// Events are part of the alert investigation workflow → alerts:read
	events := protected.Group("/events")
	events.POST("/search", handlers.SearchEvents, handlers.RequirePermission("alerts", "read"))
	events.GET("/stats", handlers.GetEventStats, handlers.RequirePermission("alerts", "read"))
	events.GET("/:id", handlers.GetEvent, handlers.RequirePermission("alerts", "read"))
	events.POST("/export", handlers.ExportEvents, handlers.RequirePermission("alerts", "read"))

	// ── Application Control endpoints (process analytics + software inventory) ──
	appControl := protected.Group("/app-control")
	appControl.GET("/process-analytics", handlers.GetProcessAnalytics, handlers.RequirePermission("endpoints", "read"))
	appControl.GET("/software-inventory", handlers.GetSoftwareInventory, handlers.RequirePermission("endpoints", "read"))
	appControl.GET("/bandwidth-analytics", handlers.GetBandwidthAnalytics, handlers.RequirePermission("endpoints", "read"))

	// ── Reliability health (operational) ──────────────────────────────────
	// Authenticated endpoint (no extra RBAC gate) to avoid false-negative
	// "backend unreachable" UI states when role permission catalogs drift.
	protected.GET("/reliability", handlers.GetReliabilityHealth)

	// ── Context-aware policy controls ──────────────────────────────────────
	contextPolicies := protected.Group("/context-policies")
	contextPolicies.GET("", handlers.ListContextPolicies, handlers.RequirePermission("settings", "read"))
	contextPolicies.POST("", handlers.CreateContextPolicy, handlers.RequirePermission("settings", "write"))
	contextPolicies.GET("/:id", handlers.GetContextPolicy, handlers.RequirePermission("settings", "read"))
	contextPolicies.PATCH("/:id", handlers.UpdateContextPolicy, handlers.RequirePermission("settings", "write"))
	contextPolicies.DELETE("/:id", handlers.DeleteContextPolicy, handlers.RequirePermission("settings", "write"))

	// ── Policy endpoints ─────────────────────────────────────────────────
	policies := protected.Group("/policies")
	policies.GET("", handlers.ListPolicies, handlers.RequirePermission("settings", "read"))
	policies.POST("", handlers.CreatePolicy, handlers.RequirePermission("settings", "write"))
	policies.GET("/:id", handlers.GetPolicy, handlers.RequirePermission("settings", "read"))
	policies.PATCH("/:id", handlers.UpdatePolicy, handlers.RequirePermission("settings", "write"))
	policies.DELETE("/:id", handlers.DeletePolicy, handlers.RequirePermission("settings", "write"))
	policies.GET("/:id/agents", handlers.GetPolicyAgents, handlers.RequirePermission("settings", "read"))

	// ── User endpoints ───────────────────────────────────────────────────
	users := protected.Group("/users")
	users.GET("", handlers.ListUsers, handlers.RequirePermission("users", "read"))
	users.POST("", handlers.CreateUser, handlers.RequirePermission("users", "write"))
	users.GET("/:id", handlers.GetUser, handlers.RequirePermission("users", "read"))
	users.PATCH("/:id", handlers.UpdateUser, handlers.RequirePermission("users", "write"))
	users.DELETE("/:id", handlers.DeleteUser, handlers.RequirePermission("users", "delete"))
	// Password change: in-handler authorization (self or admin) — no middleware
	users.POST("/:id/password", handlers.ChangePassword)

	// ── Role & Permission endpoints ──────────────────────────────────────
	roles := protected.Group("/roles")
	roles.GET("", handlers.ListRoles, handlers.RequirePermission("roles", "read"))
	roles.POST("", handlers.CreateRole, handlers.RequirePermission("roles", "write"))
	roles.PATCH("/:id/permissions", handlers.UpdateRolePermissions, handlers.RequirePermission("roles", "write"))
	roles.DELETE("/:id", handlers.DeleteRole, handlers.RequirePermission("roles", "write"))

	// Permissions listing (read access for roles:read holders)
	protected.GET("/permissions", handlers.ListPermissions, handlers.RequirePermission("roles", "read"))

	// ── Audit endpoints ──────────────────────────────────────────────────
	audit := protected.Group("/audit")
	audit.GET("/logs", handlers.ListAuditLogs, handlers.RequirePermission("audit", "read"))
	audit.GET("/logs/:id", handlers.GetAuditLog, handlers.RequirePermission("audit", "read"))

	// ── Security event audit log (persistent, filterable) ─────────────
	secEvents := protected.Group("/security")
	secEvents.GET("/events", handlers.ListSecurityEvents, handlers.RequirePermission("audit", "read"))
	secEvents.GET("/events/summary", handlers.GetSecurityEventsSummary, handlers.RequirePermission("audit", "read"))

	// ── Enrollment token management ──────────────────────────────────────
	tokens := protected.Group("/enrollment-tokens")
	tokens.GET("", handlers.ListEnrollmentTokens, handlers.RequirePermission("tokens", "read"))
	tokens.POST("", handlers.GenerateEnrollmentToken, handlers.RequirePermission("tokens", "write"))
	tokens.POST("/:id/revoke", handlers.RevokeEnrollmentToken, handlers.RequirePermission("tokens", "write"))
	tokens.DELETE("/:id", handlers.DeleteEnrollmentToken, handlers.RequirePermission("tokens", "write"))

	// ── Agent build (deployment) ─────────────────────────────────────────
	protected.POST("/agent/build", handlers.BuildAgent, handlers.RequirePermission("agents", "write"))

	// ── Agent packages (patch/upgrade) ───────────────────────────────────
	// Create package requires auth; download is tokenized + short-lived and is public.
	protected.POST("/agent/packages", handlers.CreateAgentPackage, handlers.RequirePermission("agents", "write"))
	v1.GET("/agent/packages/:id/download", handlers.DownloadAgentPackage)

	// ── Signature / malware-hash feed endpoints ──────────────────────────
	// Public (no JWT) — agents poll/download without dashboard credentials.
	v1.GET("/signatures/version", handlers.GetSignatureVersion)
	v1.GET("/signatures/feed.ndjson", handlers.GetSignatureFeed)
	// Admin (JWT-gated)
	signatures := protected.Group("/signatures")
	signatures.GET("/stats", handlers.GetSignatureStats, handlers.RequirePermission("settings", "read"))
	signatures.GET("/sync-history", handlers.GetSignatureSyncHistory, handlers.RequirePermission("settings", "read"))
	signatures.POST("/sync", handlers.TriggerSignatureSync, handlers.RequirePermission("settings", "write"))
	signatures.POST("/push-update", handlers.PushSignatureUpdateAll, handlers.RequirePermission("settings", "write"))
	signatures.GET("", handlers.ListSignatureHashes, handlers.RequirePermission("settings", "read"))

	// ── Automation endpoints ─────────────────────────────────────────────
	if handlers.AutomationHandlers != nil {
		automation := protected.Group("/automation")
		// Response Playbooks
		automation.GET("/playbooks", handlers.AutomationHandlers.ListPlaybooks, handlers.RequirePermission("responses", "read"))
		automation.POST("/playbooks", handlers.AutomationHandlers.CreatePlaybook, handlers.RequirePermission("responses", "execute"))
		automation.GET("/playbooks/:id", handlers.AutomationHandlers.GetPlaybook, handlers.RequirePermission("responses", "read"))
		automation.DELETE("/playbooks/:id", handlers.AutomationHandlers.DeletePlaybook, handlers.RequirePermission("responses", "execute"))
		// Automation Rules
		automation.GET("/rules", handlers.AutomationHandlers.ListAutomationRules, handlers.RequirePermission("responses", "read"))
		automation.POST("/rules", handlers.AutomationHandlers.CreateAutomationRule, handlers.RequirePermission("responses", "execute"))
		automation.PATCH("/rules/:id", handlers.AutomationHandlers.UpdateAutomationRule, handlers.RequirePermission("responses", "execute"))
		automation.DELETE("/rules/:id", handlers.AutomationHandlers.DeleteAutomationRule, handlers.RequirePermission("responses", "execute"))
		automation.PATCH("/rules/:id/toggle", handlers.AutomationHandlers.ToggleAutomationRule, handlers.RequirePermission("responses", "execute"))
		// Metrics and Optimizations
		automation.GET("/metrics", handlers.AutomationHandlers.GetAutomationMetrics, handlers.RequirePermission("responses", "read"))
		automation.POST("/optimize", handlers.AutomationHandlers.GetAutomationOptimizations, handlers.RequirePermission("responses", "execute"))
	}
}

// healthCheck returns server health status.
func (s *Server) healthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// readyCheck returns server readiness status.
func (s *Server) readyCheck(c echo.Context) error {
	// TODO: Check database, Redis, Kafka connectivity
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Start starts the API server.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	s.logger.WithField("addr", addr).Info("Starting REST API server")
	return s.echo.Start(addr)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down REST API server...")
	return s.echo.Shutdown(ctx)
}

// Echo returns the underlying Echo instance.
func (s *Server) Echo() *echo.Echo {
	return s.echo
}
