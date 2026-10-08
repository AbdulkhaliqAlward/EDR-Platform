// Package handlers provides the main API server setup.
package handlers

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/analytics"
	"github.com/edr-platform/sigma-engine/internal/application/scoring"
	"github.com/edr-platform/sigma-engine/internal/automation"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig configures the API server.
type ServerConfig struct {
	Address          string        `yaml:"address"`
	ReadTimeout      time.Duration `yaml:"read_timeout"`
	WriteTimeout     time.Duration `yaml:"write_timeout"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`
	APIKeys          []string      `yaml:"api_keys"`
	CORSOrigin       string        `yaml:"cors_origin"`
	JWTPublicKeyPath string        `yaml:"jwt_public_key_path"`
}

// DefaultServerConfig returns default server configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:         ":8080",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		ShutdownTimeout: 10 * time.Second,
		CORSOrigin:      "*",
	}
}

// Server is the main API server.
type Server struct {
	config     ServerConfig
	httpServer *http.Server
	router     *mux.Router
	apiV1      *mux.Router // authenticated /api/v1 routes (for late wiring)

	ruleHandler  *RuleHandler
	alertHandler *AlertHandler
	statsHandler *StatsHandler
	wsServer     *WebSocketServer
	tokenAuth    *TokenAuth
	jwtAuth      *JWTAuth
}

// NewServer creates a new API server.
func NewServer(
	config ServerConfig,
	ruleRepo database.RuleRepository,
	alertRepo database.AlertRepository,
	auditLogger *database.AuditLogger,
	riskLevels scoring.RiskLevelsConfig,
) *Server {
	router := mux.NewRouter()

	// Initialize API key auth from config or environment
	apiKeys := config.APIKeys
	if envKeys := os.Getenv("SIGMA_API_KEYS"); envKeys != "" {
		apiKeys = append(apiKeys, strings.Split(envKeys, ",")...)
	}

	var tokenAuth *TokenAuth
	if len(apiKeys) > 0 {
		tokenAuth = NewTokenAuth(apiKeys)
		logger.Infof("API authentication enabled with %d API key(s)", len(apiKeys))
	} else {
		logger.Warn("No API keys configured (SIGMA_API_KEYS) - API key authentication disabled")
	}

	// Initialize JWT auth from public key (for Dashboard tokens signed by Connection Manager)
	jwtKeyPath := config.JWTPublicKeyPath
	if envPath := os.Getenv("JWT_PUBLIC_KEY_PATH"); envPath != "" {
		jwtKeyPath = envPath
	}

	var jwtAuth *JWTAuth
	if jwtKeyPath != "" {
		var err error
		jwtAuth, err = NewJWTAuth(jwtKeyPath)
		if err != nil {
			logger.Warnf("JWT auth initialization failed (JWT auth disabled): %v", err)
		} else {
			logger.Info("JWT RSA authentication enabled (Connection Manager tokens accepted)")
		}
	} else {
		logger.Warn("No JWT public key configured (JWT_PUBLIC_KEY_PATH) - JWT authentication disabled")
	}

	// Load CORS origin from env if set
	if origin := os.Getenv("SIGMA_CORS_ORIGIN"); origin != "" {
		config.CORSOrigin = origin
	}

	s := &Server{
		config:       config,
		router:       router,
		ruleHandler:  NewRuleHandler(ruleRepo, auditLogger),
		alertHandler: NewAlertHandler(alertRepo, auditLogger, riskLevels),
		statsHandler: NewStatsHandler(alertRepo, ruleRepo),
		wsServer:     NewWebSocketServer(),
		tokenAuth:    tokenAuth,
		jwtAuth:      jwtAuth,
	}

	s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         config.Address,
		Handler:      router,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return s
}

// setupRoutes configures all API routes.
func (s *Server) setupRoutes() {
	// Global middleware (applied to all routes)
	s.router.Use(RecoveryMiddleware)
	s.router.Use(RequestIDMiddleware)
	s.router.Use(SecurityHeadersMiddleware)
	s.router.Use(loggingMiddleware)
	s.router.Use(s.corsMiddlewareConfigurable)

	// Health check (unauthenticated)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")
	s.router.HandleFunc("/ready", s.readyCheck).Methods("GET")

	// Prometheus metrics (unauthenticated)
	s.router.Handle("/metrics", promhttp.Handler())

	// API routes with authentication
	api := s.router.PathPrefix("/api/v1").Subrouter()
	s.apiV1 = api

	// Apply auth middleware: JWT (dashboard) + API key (service-to-service)
	if s.jwtAuth != nil || s.tokenAuth != nil {
		api.Use(CombinedAuthMiddleware(s.jwtAuth, s.tokenAuth))
	}

	// Apply rate limiting to API
	api.Use(RateLimitMiddleware(NewRateLimiter(100, time.Minute)))

	// Rules
	s.ruleHandler.RegisterRoutes(api)

	// WebSocket — MUST be registered before AlertHandler to prevent the
	// /sigma/alerts/{alert_id} wildcard from capturing the literal path
	// segment "stream" (gorilla/mux evaluates routes in registration order).
	s.wsServer.RegisterRoutes(api)

	// Alerts (registered after WebSocket so {alert_id} wildcard doesn't shadow /stream)
	s.alertHandler.RegisterRoutes(api)

	// Stats
	s.statsHandler.RegisterRoutes(api)
}

// SetPerformanceMetrics injects a real-time metrics provider into the stats handler.
func (s *Server) SetPerformanceMetrics(provider PerformanceMetricsProvider) {
	s.statsHandler.SetPerformanceMetrics(provider)
}

// WireCorrelationAPI registers correlation/incident HTTP routes backed by the
// same in-memory CorrelationManager instance used by the Kafka EventLoop.
// Safe to call before Start(); may be called after NewServer.
func (s *Server) WireCorrelationAPI(mgr *analytics.CorrelationManager) {
	RegisterCorrelationRoutes(s.apiV1, mgr)
}

// WireAutomationAPI registers playbook, escalation, and notification HTTP routes.
// Pass the same instances used by the Kafka event loop so API changes affect live automation.
// Safe to call before Start(). Nil arguments skip wiring.
func (s *Server) WireAutomationAPI(
	notifier *automation.NotificationManager,
	playbooks *automation.PlaybookManager,
	escalations *automation.EscalationManager,
) {
	if s.apiV1 == nil || notifier == nil || playbooks == nil || escalations == nil {
		return
	}
	NewAutomationHandler(playbooks, escalations, notifier).RegisterRoutes(s.apiV1)
}

// corsMiddlewareConfigurable adds CORS headers using configured origin.
func (s *Server) corsMiddlewareConfigurable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := s.config.CORSOrigin
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// healthCheck handles GET /health
func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// readyCheck handles GET /ready
func (s *Server) readyCheck(w http.ResponseWriter, r *http.Request) {
	// TODO: Check database and Kafka connectivity
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ready",
	})
}

// Start starts the API server.
func (s *Server) Start() error {
	s.wsServer.Start()

	logger.Infof("Starting API server on %s", s.config.Address)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down API server...")
	return s.httpServer.Shutdown(ctx)
}

// Router returns the router for testing.
func (s *Server) Router() *mux.Router {
	return s.router
}

// WebSocketServer returns the WebSocket server.
func (s *Server) WebSocketServer() *WebSocketServer {
	return s.wsServer
}

// loggingMiddleware logs all requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Infof("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// corsMiddleware adds CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SetRuleRuntime wires validation and activation before serving requests.
func (s *Server) SetRuleRuntime(runtime RuleRuntime) { s.ruleHandler.runtime = runtime }
