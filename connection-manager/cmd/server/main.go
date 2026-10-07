// Package main is the entry point for the connection-manager server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/config"
	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/database"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/api"
	"github.com/edr-platform/connection-manager/pkg/audit"
	"github.com/edr-platform/connection-manager/pkg/handlers"
	"github.com/edr-platform/connection-manager/pkg/kafka"
	"github.com/edr-platform/connection-manager/pkg/metrics"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/playbook"
	"github.com/edr-platform/connection-manager/pkg/security"
	"github.com/edr-platform/connection-manager/pkg/server"
)

// generateRandomPassword returns a URL-safe 24-byte (=32-char base64) random
// string suitable for a one-shot bootstrap admin password. We use crypto/rand
// so the seed is unpredictable even with full filesystem access.
func generateRandomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// seedDefaultAdmin creates a bootstrap admin account on the very first boot
// of an empty users table. Behaviour:
//
//   - Username, email and password are read from the environment:
//     INITIAL_ADMIN_USERNAME (default "admin"),
//     INITIAL_ADMIN_EMAIL    (default "admin@edr.local"),
//     INITIAL_ADMIN_PASSWORD (if empty, a random one is generated).
//
//   - INSERT … ON CONFLICT DO NOTHING means existing admin credentials
//     (and any password changes made by operators) are NEVER overwritten
//     on reboot.
//
//   - The plaintext password is logged ONCE — only on the boot where the
//     row was actually inserted. Operators are expected to capture it from
//     stdout/stderr and rotate it via the dashboard.
func seedDefaultAdmin(ctx context.Context, dbPool *database.PostgresPool, logger *logrus.Logger) {
	pool := dbPool.Pool()

	username := strings.TrimSpace(os.Getenv("INITIAL_ADMIN_USERNAME"))
	if username == "" {
		username = "admin"
	}
	email := strings.TrimSpace(os.Getenv("INITIAL_ADMIN_EMAIL"))
	if email == "" {
		email = "admin@edr.local"
	}

	password := os.Getenv("INITIAL_ADMIN_PASSWORD")
	generated := false
	if password == "" {
		gen, err := generateRandomPassword()
		if err != nil {
			logger.Errorf("Failed to generate seed password: %v", err)
			return
		}
		password = gen
		generated = true
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("Failed to hash seed password: %v", err)
		return
	}

	now := time.Now()
	adminID := uuid.New()
	tag, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash, full_name, role, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (username) DO NOTHING`,
		adminID,
		username,
		email,
		string(hashedPassword),
		"Administrator",
		models.UserRoleAdmin,
		models.UserStatusActive,
		now, now,
	)
	if err != nil {
		logger.Errorf("Failed to seed default admin user: %v", err)
		return
	}
	if tag.RowsAffected() > 0 {
		if generated {
			// Print the only copy of the password the operator will ever
			// see. Use a hard-to-miss banner so it's not lost in the noise.
			logger.Warn("================================================================")
			logger.Warnf("🔑 BOOTSTRAP ADMIN CREATED — username: %q", username)
			logger.Warnf("🔑 BOOTSTRAP ADMIN PASSWORD (shown ONCE): %s", password)
			logger.Warn("🔑 Capture it now and change it from the dashboard ASAP.")
			logger.Warn("================================================================")
		} else {
			logger.Infof("🔑 Bootstrap admin %q created from INITIAL_ADMIN_PASSWORD env var.", username)
		}
	} else {
		logger.Debug("Admin account already exists — skipping seed")
	}
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	flag.Parse()

	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	logger.SetOutput(os.Stdout)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Set log level
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	logger.Info("Starting Connection Manager Server...")
	logger.WithFields(logrus.Fields{
		"grpc_port": cfg.Server.GRPCPort,
		"http_port": cfg.Server.HTTPPort,
	}).Info("Configuration loaded")

	// Initialize Redis client (optional — server runs in degraded mode if unavailable)
	var redisClient *cache.RedisClient
	if c, err := cache.NewRedisClient(&cache.RedisConfig{
		Addr:         cfg.Redis.Addr,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		PoolTimeout:  cfg.Redis.PoolTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
	}, logger); err != nil {
		logger.Warnf("Redis unavailable, running in degraded mode (dedup, rate limit, agent status, and JWT blocklist disabled): %v", err)
		redisClient = nil
	} else {
		redisClient = c
		defer redisClient.Close()
	}

	// ── Encrypted KeyStore Bootstrap ─────────────────────────────────────
	// All private keys (ca.key, server.key, jwt_private.pem) are stored
	// encrypted at rest using AES-256-GCM with an Argon2id-derived KEK.
	// On first boot: generates keys → encrypts → deletes plaintext.
	// On subsequent boots: decrypts .enc files into memory.
	var tlsConfig *tls.Config
	var keyStore *security.KeyStore

	if grpcInsecure() {
		logger.Warn("GRPC_INSECURE is set — gRPC server will use PLAINTEXT (no TLS). Use only for debugging.")
		tlsConfig = nil
	} else {
		masterPassphrase := os.Getenv("MASTER_KEY_PASSPHRASE")
		if masterPassphrase == "" {
			logger.Fatal("MASTER_KEY_PASSPHRASE environment variable is required. " +
				"This passphrase is used to derive the Key Encryption Key (KEK) that protects " +
				"ca.key, server.key, and jwt_private.pem at rest. " +
				"Set it in your .env file or environment before starting the server.")
		}

		caKeyPath := filepath.Join(filepath.Dir(cfg.Server.CACertPath), "ca.key")
		certsDir := filepath.Dir(cfg.Server.CACertPath)
		var ksErr error
		keyStore, ksErr = security.NewKeyStore(masterPassphrase, security.KeyStorePaths{
			CACertPath:       cfg.Server.CACertPath,
			CAKeyPath:        caKeyPath,
			ServerCertPath:   cfg.Server.TLSCertPath,
			ServerKeyPath:    cfg.Server.TLSKeyPath,
			JWTPrivatePath:   cfg.JWT.PrivateKeyPath,
			JWTPublicPath:    cfg.JWT.PublicKeyPath,
			UninstallKeyPath: filepath.Join(certsDir, "uninstall_sign.key"),
			UninstallPubPath: filepath.Join(certsDir, "uninstall_sign.pub"),
		}, logger)
		if ksErr != nil {
			logger.Fatalf("KeyStore creation failed: %v", ksErr)
		}

		if ksErr = keyStore.Initialize(masterPassphrase); ksErr != nil {
			logger.Fatalf("KeyStore initialization failed: %v", ksErr)
		}

		// Build TLS config from in-memory keys (server.key never read from disk).
		var tlsErr error
		tlsConfig, tlsErr = security.LoadServerTLSConfigFromMemory(
			keyStore.ServerTLSCert(),
			keyStore.CACertPEM(),
		)
		if tlsErr != nil {
			logger.Fatalf("Failed to build TLS configuration from KeyStore: %v", tlsErr)
		}
	}

	// Initialize JWT Manager from KeyStore (in-memory keys) or fall back to mTLS-only.
	var jwtManager *security.JWTManager
	if keyStore != nil && keyStore.JWTPrivateKey() != nil {
		jwtManager = security.NewJWTManagerFromKeys(
			keyStore.JWTPrivateKey(),
			keyStore.JWTPublicKey(),
			cfg.JWT.Issuer,
			cfg.JWT.Audience,
			cfg.JWT.AccessTTL,
			cfg.JWT.RefreshTTL,
		)
		logger.Info("JWT Manager initialized from KeyStore — dual auth (mTLS + JWT) enabled")
	} else if cfg.JWT.PrivateKeyPath != "" && cfg.JWT.PublicKeyPath != "" {
		// Fallback for GRPC_INSECURE mode: load from disk paths (no KeyStore).
		var jwtErr error
		jwtManager, jwtErr = security.NewJWTManager(
			cfg.JWT.PrivateKeyPath,
			cfg.JWT.PublicKeyPath,
			cfg.JWT.Issuer,
			cfg.JWT.Audience,
			cfg.JWT.AccessTTL,
			cfg.JWT.RefreshTTL,
		)
		if jwtErr != nil {
			logger.Warnf("JWT Manager initialization failed (mTLS-only mode): %v", jwtErr)
			jwtManager = nil
		} else {
			logger.Info("JWT Manager initialized from disk — dual auth (mTLS + JWT) enabled")
		}
	} else {
		logger.Warn("JWT key paths not configured - running in mTLS-only mode")
	}

	// Initialize PostgreSQL database (optional - registration disabled without it)
	// We keep the pool reference alive beyond this block so the EventFallbackStore
	// can use it for durable event storage when Kafka is unavailable.
	ctx := context.Background()
	var agentSvc service.AgentService
	var certSvc service.CertificateService    // hoisted for renewal worker access
	var crlCache *repository.CRLCache         // hoisted for interceptor injection
	var authSvc service.AuthService
	var commandApprovalSvc service.CommandApprovalService
	var enrollmentTokenRepo repository.EnrollmentTokenRepository
	var agentRepo repository.AgentRepository     // hoisted for sweeper access
	var commandRepo repository.CommandRepository // hoisted for C2 injection
	var forensicRepo repository.ForensicRepository
	var quarantineRepo repository.QuarantineRepository
	var auditRepo repository.AuditLogRepository // hoisted for audit log API
	var alertRepo repository.AlertRepository    // hoisted for alert stats API
	var playbookRepo repository.ResponsePlaybookRepository
	var automationRuleRepo repository.AutomationRuleRepository
	var executionRepo repository.PlaybookExecutionRepository
	var automationMetricsRepo repository.AutomationMetricsRepository
	var agentPackageRepo repository.AgentPackageRepository
	var auditLogger *audit.Logger               // non-blocking security event logger
	var dbPool *database.PostgresPool // scoped outside if-block for fallback access

	dbPoolInst, dbErr := database.NewPostgresPool(ctx, &database.PostgresConfig{
		Host:            cfg.Database.Host,
		Port:            cfg.Database.Port,
		User:            cfg.Database.User,
		Password:        cfg.Database.Password,
		Database:        cfg.Database.Name,
		SSLMode:         cfg.Database.SSLMode,
		MaxConns:        int32(cfg.Database.MaxOpenConns),
		MinConns:        int32(cfg.Database.MaxIdleConns),
		MaxConnLifetime: cfg.Database.ConnMaxLifetime,
		MaxConnIdleTime: cfg.Database.ConnMaxIdleTime,
	}, logger)
	if dbErr != nil {
		logger.Warnf("Failed to connect to PostgreSQL (agent registration disabled): %v", dbErr)
	} else {
		dbPool = dbPoolInst
		defer dbPool.Close()

		// ── Auto-migrate: apply any pending SQL migrations ──
		dbCfg := &database.PostgresConfig{
			Host:     cfg.Database.Host,
			Port:     cfg.Database.Port,
			User:     cfg.Database.User,
			Password: cfg.Database.Password,
			Database: cfg.Database.Name,
			SSLMode:  cfg.Database.SSLMode,
		}
		if err := database.RunMigrations(dbCfg, logger); err != nil {
			logger.Fatalf("Auto-migration failed: %v", err)
		}

		pool := dbPool.Pool()
		agentRepo = repository.NewPostgresAgentRepository(pool)
		tokenRepo := repository.NewPostgresInstallationTokenRepository(pool)
		enrollmentTokenRepo = repository.NewPostgresEnrollmentTokenRepository(pool)
		auditRepo = repository.NewPostgresAuditLogRepository(pool)
		certRepo := repository.NewPostgresCertificateRepository(pool)
		commandRepo = repository.NewPostgresCommandRepository(pool)
		forensicRepo = repository.NewPostgresForensicRepository(pool)
		alertRepo = repository.NewPostgresAlertRepository(pool)
		quarantineRepo = repository.NewPostgresQuarantineRepository(pool)
		playbookRepo = repository.NewPostgresResponsePlaybookRepository(pool)
		automationRuleRepo = repository.NewPostgresAutomationRuleRepository(pool)
		executionRepo = repository.NewPostgresPlaybookExecutionRepository(pool)
		automationMetricsRepo = repository.NewPostgresAutomationMetricsRepository(pool)

		// Non-blocking security audit logger — persists to security_events table.
		auditLogger = audit.New(pool, logger)
		logger.Info("[Audit] Security event logger started")

		// CRL cache: in-memory, DB-backed, never hits DB on hot path.
		crlCache = repository.NewCRLCache(certRepo, logger)

		// Certificate service: prefer KeyStore (in-memory CA key) over disk paths.
		if keyStore != nil {
			certSvc = service.NewCertificateServiceWithKeys(
				certRepo, agentRepo, auditRepo, redisClient, logger,
				keyStore.CACert(), keyStore.CAKey(), keyStore.CACertPEM(),
			)
		} else {
			caCertPath := cfg.Server.CACertPath
			caKeyPath := filepath.Join(filepath.Dir(caCertPath), "ca.key")
			certSvc = service.NewCertificateService(
				certRepo, agentRepo, auditRepo, redisClient, logger,
				caCertPath, caKeyPath,
			)
		}
		// Inject audit logger into cert service (type-assert to concrete impl).
		if impl, ok := certSvc.(interface{ SetAuditLogger(*audit.Logger) }); ok {
			impl.SetAuditLogger(auditLogger)
		}

		// Create agent service (with cert service for auto-issuance on Register)
		agentSvc = service.NewAgentService(agentRepo, tokenRepo, enrollmentTokenRepo, auditRepo, redisClient, logger, certSvc)

		// Create user repository and auth service for dashboard login
		userRepo := repository.NewPostgresUserRepository(pool)
		authSvc = service.NewAuthService(userRepo, auditRepo, jwtManager, redisClient, logger)

		// ── MFA wiring ───────────────────────────────────────────────────
		// Build the email sender from config, then the MFA service, then
		// attach the MFA service to the auth service. Each piece is
		// optional: if SMTP is disabled we simply don't wire MFA, and
		// AuthService falls back to refusing login for any user whose
		// mfa_enabled=true (secure default).
		emailSvc := service.NewEmailService(service.SMTPSettings{
			Host:     cfg.SMTP.Host,
			Port:     cfg.SMTP.Port,
			Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password,
			From:     cfg.SMTP.From,
			UseTLS:   cfg.SMTP.UseTLS,
			StartTLS: cfg.SMTP.StartTLS,
			Enabled:  cfg.SMTP.Enabled,
		}, logger)
		if emailSvc.Enabled() {
			mfaSvc := service.NewMFAService(redisClient, emailSvc, logger)
			if withMFA, ok := authSvc.(service.AuthServiceWithMFA); ok {
				withMFA.SetMFAService(mfaSvc)
				logger.WithField("from", emailSvc.From()).
					Info("MFA (email OTP) enabled")
			}

			// ── Out-of-band manual-command approval (EC2_EMAIL_VERIFY) ───
			// Builds the approval service iff the second-channel mailbox
			// is configured. When unset we leave commandApprovalSvc nil
			// and the API gate becomes a no-op (backwards compatible).
			verifyAddr := strings.TrimSpace(os.Getenv("EC2_EMAIL_VERIFY"))
			if verifyAddr != "" {
				commandApprovalSvc = service.NewCommandApprovalService(redisClient, emailSvc, verifyAddr, logger)
				logger.WithField("verify_to", verifyAddr).
					Info("Manual-command approval (email OTP) enabled — every dashboard-issued command will require an out-of-band code")
			} else {
				logger.Warn("EC2_EMAIL_VERIFY not set — manual-command approval gate is DISABLED. " +
					"Set EC2_EMAIL_VERIFY=<approver@your-domain> to require an OTP for every dashboard-issued command.")
			}
		} else {
			logger.Warn("SMTP disabled — MFA email delivery unavailable. " +
				"Users with mfa_enabled=true will be refused login until SMTP is configured.")
			logger.Warn("SMTP disabled — manual-command approval is DISABLED for the same reason.")
		}

		logger.Info("Database connected - agent registration enabled")

		// Seed default admin user if no users exist
		seedDefaultAdmin(ctx, dbPool, logger)
	}

	// =========================================================================
	// PHASE 1: Initialize Kafka Producer, Metrics, and Handlers
	// These are the components that were missing from the original code,
	// causing StreamEvents and Heartbeat RPCs to be dead (no-op stubs).
	// =========================================================================

	// Initialize Prometheus metrics for observability
	edrMetrics := metrics.NewMetrics("edr")
	logger.Info("Prometheus metrics initialized")

	// Initialize Kafka producer (graceful: skip if disabled or unreachable)
	// When Kafka is unavailable, EventHandler will fall back to PostgreSQL
	// storage so no telemetry data is lost.
	var kafkaProducer *kafka.EventProducer
	if cfg.Kafka.Enabled {
		producerCfg := &kafka.ProducerConfig{
			Brokers:     cfg.Kafka.Brokers,
			Topic:       cfg.Kafka.Topic,
			DLQTopic:    cfg.Kafka.DLQTopic,
			Compression: cfg.Kafka.Compression,
			Acks:        cfg.Kafka.Acks,
			MaxRetries:  cfg.Kafka.MaxRetries,
			BatchSize:   cfg.Kafka.BatchSize,
			Timeout:     cfg.Kafka.Timeout,
		}

		var kafkaErr error
		kafkaProducer, kafkaErr = kafka.NewEventProducer(producerCfg, edrMetrics, logger)
		if kafkaErr != nil {
			// Kafka failure is NOT fatal — EventHandler can fall back to DB.
			// This is a deliberate design choice: an EDR system must never
			// refuse telemetry just because Kafka is temporarily down.
			logger.Warnf("Kafka producer init failed (events will fall back to DB): %v", kafkaErr)
			kafkaProducer = nil
		} else {
			defer kafkaProducer.Close()
			logger.Info("Kafka producer connected")
		}
	} else {
		logger.Warn("Kafka disabled in config — events will be stored via DB fallback")
	}

	// Initialize rate limiter for event ingestion
	// 1000 events/sec with 2x burst allows healthy agents to send batches
	// without being throttled, while protecting the server from floods.
	rateLimiter := cache.NewRateLimiter(redisClient, 1000, 2.0)

	// Create EventHandler — the core telemetry pipeline.
	// Depends on: Redis (dedup, agent-status), RateLimiter, Kafka (primary), Metrics.
	evtHandler := handlers.NewEventHandler(logger, redisClient, rateLimiter, kafkaProducer, edrMetrics)
	var fallbackStore *handlers.EventFallbackStore

	// Wire up the PostgreSQL fallback store for data durability.
	// When Kafka is unavailable, events are persisted to PostgreSQL so they
	// can be replayed later. This completes the 3-tier delivery guarantee:
	// Kafka primary → Kafka DLQ → PostgreSQL fallback.
	if dbPool != nil {
		fallback := handlers.NewEventFallbackStore(dbPool.Pool(), edrMetrics, logger)
		if fallback != nil {
			// Auto-create the fallback table if it doesn't exist.
			// This is safe to call on every startup (CREATE IF NOT EXISTS).
			if err := fallback.EnsureTable(ctx); err != nil {
				logger.Warnf("Failed to create fallback table (DB fallback disabled): %v", err)
			} else {
				fallbackStore = fallback
				evtHandler.SetFallbackStore(fallback)
				defer fallback.Close() // drain async writer workers on shutdown
				logger.Info("Event DB fallback store enabled (async workers started)")

				// Start the replay worker that re-publishes unreplayed events
				// from the fallback table back to Kafka when connectivity is restored.
				replayWorker := handlers.NewFallbackReplayWorker(dbPool.Pool(), kafkaProducer, logger)
				if replayWorker != nil {
					replayCtx, replayCancel := context.WithCancel(context.Background())
					defer replayCancel()
					go replayWorker.Start(replayCtx)
				}
			}
		}
	} else {
		logger.Warn("No DB available — event DB fallback disabled (data loss risk if Kafka is also down)")
	}
	logger.Info("EventHandler created")

	// Create HeartbeatHandler — agent health reporting.
	// Depends on: Redis (real-time status), AgentService (DB persistence).
	// agentSvc may be nil if DB is unavailable — HeartbeatHandler handles this gracefully.
	hbHandler := handlers.NewHeartbeatHandler(logger, redisClient, agentSvc)
	logger.Info("HeartbeatHandler created")

	// Create gRPC server with ALL handlers injected
	grpcServer, err := server.NewServer(cfg, logger, redisClient, tlsConfig, jwtManager, agentSvc, evtHandler, hbHandler)
	if err != nil {
		logger.Fatalf("Failed to create gRPC server: %v", err)
	}
	if forensicRepo != nil {
		grpcServer.SetForensicRepo(forensicRepo)
	}

	// Build REST API config (dashboard /api/v1): use API config with HTTP port so one server serves both.
	apiCfg := cfg.API
	apiCfg.Port = cfg.Server.HTTPPort
	restAPIServer := api.NewServer(&apiCfg, logger, edrMetrics)
	// Prometheus metrics on same server (lifecycle managed with REST API).
	restAPIServer.Echo().GET(cfg.Monitoring.MetricsPath, echo.WrapHandler(promhttp.Handler()))

	var automationHandlers *api.AutomationHandlers
	if dbPool != nil {
		metricsService := service.NewMetricsService(logger, automationMetricsRepo)
		commandService := service.NewCommandService(logger, commandRepo, executionRepo, automationMetricsRepo)
		mlOptimizer := service.NewMLOptimizer(logger, automationMetricsRepo, automationRuleRepo)
		notificationService := service.NewNotificationService(logger)
		automationService := service.NewAutomationService(logger, alertRepo, playbookRepo, automationRuleRepo, executionRepo, commandService, notificationService, metricsService, mlOptimizer)
		automationHandlers = api.NewAutomationHandlers(logger, automationService, metricsService)
	}

	apiHandlers := api.NewHandlers(logger, jwtManager, redisClient, rateLimiter, agentSvc, authSvc, cfg.Server.CACertPath, enrollmentTokenRepo, automationHandlers)
	// Wire fallback store stats into REST API reliability endpoint.
	// Safe even if nil (endpoint returns enabled=false + reason).
	apiHandlers.SetFallbackStore(fallbackStore)
	// Wire the optional out-of-band approval service. nil is fine — when
	// it is nil the gate becomes a no-op so deployments without SMTP /
	// EC2_EMAIL_VERIFY behave exactly as before.
	apiHandlers.SetCommandApprovalService(commandApprovalSvc)

	// Wire the Ed25519 signer for offline uninstall tokens. nil is fine — the
	// mint endpoint then reports the feature as unavailable (503) and nothing
	// else is affected.
	if keyStore != nil {
		apiHandlers.SetUninstallSigner(keyStore.UninstallSigningKey(), 0)
	}

	// Master switch for admin-authored custom commands (default OFF). When off,
	// only built-in diagnostics and server-side library/playbook commands run.
	allowCustom := strings.EqualFold(strings.TrimSpace(os.Getenv("EDR_ALLOW_CUSTOM_COMMANDS")), "true")
	apiHandlers.SetAllowCustomCommands(allowCustom)
	if allowCustom {
		logger.Warn("EDR_ALLOW_CUSTOM_COMMANDS=true — admins can run custom commands on agents (admin role + approval + reason + audit enforced)")
	} else {
		logger.Info("Custom commands are disabled (EDR_ALLOW_CUSTOM_COMMANDS not set to true)")
	}

	// Wire the gRPC server's AgentRegistry into REST API handlers for C2 command routing.
	// Without this, POST /agents/:id/commands returns 503 (registry == nil).
	apiHandlers.SetRegistry(grpcServer.GetRegistry())

	// Wire the gRPC address so isolate commands automatically inject server_address
	// into their parameters. The agent needs this to build correct ALLOW firewall rules.
	// NOTE: The address here must match what the agent uses to connect.
	//       Env var C2_GRPC_ADDRESS overrides the default "host:port" construct.
	c2GRPCAddress := os.Getenv("C2_GRPC_ADDRESS")
	if c2GRPCAddress == "" {
		c2GRPCAddress = fmt.Sprintf("localhost:%d", cfg.Server.GRPCPort)
	}
	apiHandlers.SetGRPCAddress(c2GRPCAddress)
	logger.Infof("[C2] Isolation server_address configured as %s", c2GRPCAddress)

	// Wire CommandRepository into REST handlers and gRPC server for C2 persistence.
	// Also wire into EventHandler for pending command re-delivery on agent reconnect.
	if commandRepo != nil {
		apiHandlers.SetCommandRepo(commandRepo)
		grpcServer.SetCommandRepo(commandRepo)
		evtHandler.SetCommandRepo(commandRepo) // enables re-delivery on reconnect
		logger.Info("C2 command persistence enabled (commands table + pending re-delivery)")
	}
	if quarantineRepo != nil {
		evtHandler.SetQuarantineRepo(quarantineRepo)
		apiHandlers.SetQuarantineRepo(quarantineRepo)
		grpcServer.SetQuarantineRepo(quarantineRepo)
		logger.Info("Quarantine inventory API enabled (agent_quarantine_items)")
	}

	// Wire AuditLogRepository into REST handlers for the Audit Logs page.
	if auditRepo != nil {
		apiHandlers.SetAuditRepo(auditRepo)
		logger.Info("Audit log querying enabled")
	}

	// Wire security event logger + query repo into REST handlers.
	if auditLogger != nil {
		apiHandlers.SetAuditLogger(auditLogger)
		if dbPool != nil {
			apiHandlers.SetSecurityEventRepo(audit.NewRepository(dbPool.Pool()))
		}
		logger.Info("[Audit] Security event endpoints enabled (/api/v1/security/events)")
	}

	// Wire AlertRepository into REST handlers for Alert Stats and querying.
	if alertRepo != nil {
		apiHandlers.SetAlertRepo(alertRepo)
		logger.Info("Alert querying and stats enabled")
	}

	// Wire UserRepository + RoleRepository into REST handlers for RBAC.
	if dbPool != nil {
		pool := dbPool.Pool()
		apiHandlers.SetUserRepo(repository.NewPostgresUserRepository(pool))
		apiHandlers.SetRoleRepo(repository.NewPostgresRoleRepository(pool))
		apiHandlers.SetSessionRepo(repository.NewPostgresSessionRepository(pool))
		apiHandlers.SetContextPolicyRepo(repository.NewPostgresContextPolicyRepository(pool))
		agentPackageRepo = repository.NewPostgresAgentPackageRepository(pool)
		apiHandlers.SetAgentPackageRepo(agentPackageRepo)
		apiHandlers.SetAgentPatchProfileRepo(repository.NewPostgresAgentPatchProfileRepository(pool))
		// Event storage/search for dashboard investigations
		eventRepo := repository.NewPostgresEventRepository(pool)
		apiHandlers.SetEventRepo(eventRepo)
		evtHandler.SetEventRepo(eventRepo)
		apiHandlers.SetForensicRepo(forensicRepo)
		logger.Info("User management and RBAC enabled")

		// ── Post-Isolation Pipeline ──────────────────────────────────────
		// Wire incident repository + playbook engine.
		incidentRepo := repository.NewPostgresIncidentRepository(pool)
		apiHandlers.SetIncidentRepo(incidentRepo)
		grpcServer.SetIncidentRepo(incidentRepo)

		vulnRepo := repository.NewPostgresVulnerabilityRepository(pool)
		apiHandlers.SetVulnRepo(vulnRepo)
		apiHandlers.SetVulnScannerIngest(service.NewVulnScannerIngestService(logger))
		evtHandler.SetVulnerabilityRepo(vulnRepo)
		logger.Info("Vulnerability findings API enabled (vulnerability_findings)")

		// CISA KEV catalog sync — runs once at startup, then daily.
		kevSync := service.NewKEVSyncService(vulnRepo, logger)
		apiHandlers.SetKEVSync(kevSync)
		go kevSync.Run(context.Background())
		logger.Info("CISA KEV sync service enabled (24h interval)")

		apiHandlers.SetSiemRepo(repository.NewPostgresSiemConnectorRepository(pool))
		logger.Info("SIEM connectors API enabled (siem_connectors)")

		apiHandlers.SetResponseScriptRepo(repository.NewPostgresResponseScriptRepository(pool))
		logger.Info("Response script library API enabled (response_scripts)")

		malwareHashRepo := repository.NewPostgresMalwareHashRepository(pool)
		apiHandlers.SetMalwareHashRepo(malwareHashRepo)
		sigSyncSvc := service.NewSignatureSyncService(malwareHashRepo, logger)
		apiHandlers.SetSignatureSyncSvc(sigSyncSvc)
		go sigSyncSvc.Run(context.Background())
		logger.Info("Signature sync service enabled (MalwareBazaar → PostgreSQL, 6h interval)")

		if commandRepo != nil {
			pb := playbook.NewEngine(logger, incidentRepo, commandRepo, grpcServer.GetRegistry())
			grpcServer.SetPlaybookEngine(pb)
			logger.Info("Post-isolation playbook engine enabled")
		}
	}

	restAPIServer.RegisterRoutes(apiHandlers)

	// Start REST API server (healthz, readyz, /api/v1/*, metrics) on HTTP port
	go func() {
		if err := restAPIServer.Start(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("REST API server error: %v", err)
		}
	}()

	// =========================================================================
	// STALE AGENT SWEEPER: mark agents offline if last_seen > 5 minutes
	// =========================================================================
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	defer sweepCancel()
	if agentRepo != nil {
		go staleAgentSweeper(sweepCtx, agentRepo, logger)
		logger.Info("Stale agent sweeper started (interval: 15s, threshold: 1m)")
	}
	if agentPackageRepo != nil {
		go expiredAgentPackageSweeper(sweepCtx, agentPackageRepo, logger)
		logger.Info("Expired agent package sweeper started (interval: 1m)")
	}

	// Wire CRL cache into gRPC interceptor (DB-backed, cache-only hot path).
	if crlCache != nil && grpcServer.GetInterceptor() != nil {
		grpcServer.GetInterceptor().SetCRLCache(crlCache)
		defer crlCache.Stop()
		logger.Info("[CRL] DB-backed in-memory CRL cache wired into gRPC interceptor")
	}
	// Wire audit logger into gRPC interceptor for CRL rejection events.
	if auditLogger != nil && grpcServer.GetInterceptor() != nil {
		grpcServer.GetInterceptor().SetAuditLogger(auditLogger)
	}

	// Start certificate auto-renewal worker (every 6h, 30-day look-ahead).
	if certSvc != nil {
		renewalCtx, renewalCancel := context.WithCancel(context.Background())
		defer renewalCancel()
		go certSvc.StartRenewalWorker(renewalCtx, 30)
		logger.Info("[CertRenewal] Auto-renewal worker started (6h interval, 30-day look-ahead)")
	}

	// Start gRPC server in goroutine
	go func() {
		if err := grpcServer.Start(); err != nil {
			logger.Fatalf("gRPC server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutdown signal received, initiating graceful shutdown...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Shutdown REST API (HTTP) server first
	if err := restAPIServer.Shutdown(shutdownCtx); err != nil {
		logger.Warnf("REST API server shutdown error: %v", err)
	}

	// Shutdown gRPC server
	if err := grpcServer.Shutdown(shutdownCtx); err != nil {
		logger.Warnf("gRPC server shutdown error: %v", err)
	}

	// Flush the security audit logger — drain any buffered events.
	if auditLogger != nil {
		auditLogger.Shutdown(shutdownCtx)
		logger.Info("[Audit] Security event logger flushed")
	}

	logger.Info("Server stopped")
}

// startHTTPServer starts the HTTP server for health checks and metrics.
func startHTTPServer(cfg *config.Config, logger *logrus.Logger, redis *cache.RedisClient) *http.Server {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc(cfg.Monitoring.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		health := checkHealth(r.Context(), redis)

		status := http.StatusOK
		if health.Status == "unhealthy" {
			status = http.StatusServiceUnavailable
		} else if health.Status == "degraded" {
			status = http.StatusOK // Still return 200 for degraded
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(health.ToJSON()))
	})

	// Prometheus metrics endpoint
	if cfg.Monitoring.Enabled {
		mux.Handle(cfg.Monitoring.MetricsPath, promhttp.Handler())
	}

	// Ready endpoint (for K8s readiness probe)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Check if all dependencies are ready
		health := checkHealth(r.Context(), redis)
		if health.Status == "unhealthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	addr := ":" + strconv.Itoa(cfg.Server.HTTPPort)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logger.Infof("HTTP server listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	return server
}

// HealthStatus represents the health check response.
type HealthStatus struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
	Timestamp  string            `json:"timestamp"`
}

// ToJSON converts HealthStatus to a JSON string.
func (h *HealthStatus) ToJSON() string {
	data, err := json.Marshal(h)
	if err != nil {
		return `{"status":"error","message":"failed to serialize health status"}`
	}
	return string(data)
}

// checkHealth checks the health of all components.
func checkHealth(ctx context.Context, redis *cache.RedisClient) *HealthStatus {
	health := &HealthStatus{
		Status:     "healthy",
		Components: make(map[string]string),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	// Check Redis (nil when running in degraded mode)
	if redis == nil {
		health.Components["redis"] = "unavailable (degraded mode)"
		health.Status = "degraded"
	} else if err := redis.Client().Ping(ctx).Err(); err != nil {
		health.Components["redis"] = "unhealthy"
		health.Status = "degraded"
	} else {
		health.Components["redis"] = "ok"
	}

	// TODO: Check database connection
	health.Components["database"] = "ok"

	// gRPC server is always ok if we're responding
	health.Components["grpc"] = "ok"

	return health
}

// grpcInsecure returns true when GRPC_INSECURE env is set (plaintext gRPC for debugging).
func grpcInsecure() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("GRPC_INSECURE")))
	return v == "1" || v == "true"
}

// staleAgentSweeper runs a periodic sweep to mark zombie agents as offline.
// An agent is considered stale if its last_seen timestamp is older than 1 minute.
// Sweep interval: 15s — ensures offline detection within ~75 seconds.
func staleAgentSweeper(ctx context.Context, repo repository.AgentRepository, logger *logrus.Logger) {
	const threshold = 1 * time.Minute
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stale agent sweeper stopped")
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			affected, err := repo.MarkStaleOffline(sweepCtx, threshold)
			cancel()
			if err != nil {
				logger.Errorf("Stale agent sweep failed: %v", err)
			} else if affected > 0 {
				logger.Infof("Stale agent sweep: marked %d zombie agents as offline", affected)
			}
		}
	}
}

// expiredAgentPackageSweeper removes expired package files and DB rows.
// This enforces short-lived download links even if they are never redeemed.
func expiredAgentPackageSweeper(ctx context.Context, repo repository.AgentPackageRepository, logger *logrus.Logger) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Expired agent package sweeper stopped")
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			expiredRows, err := repo.ListExpired(sweepCtx, time.Now())
			cancel()
			if err != nil {
				logger.Errorf("Expired agent package sweep failed: %v", err)
				continue
			}
			if len(expiredRows) == 0 {
				continue
			}

			deleted := 0
			for _, row := range expiredRows {
				if row == nil {
					continue
				}
				if row.StoragePath != "" {
					_ = os.Remove(row.StoragePath)
				}
				delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := repo.Delete(delCtx, row.ID); err == nil {
					deleted++
				}
				delCancel()
			}
			if deleted > 0 {
				logger.Infof("Expired agent package sweep: removed %d package(s)", deleted)
			}
		}
	}
}
