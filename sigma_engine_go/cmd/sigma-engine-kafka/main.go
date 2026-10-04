package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/alert"
	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/analytics"
	"github.com/edr-platform/sigma-engine/internal/application/scoring"
	"github.com/edr-platform/sigma-engine/internal/automation"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/handlers"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/config"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	infraKafka "github.com/edr-platform/sigma-engine/internal/infrastructure/kafka"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	rulecache "github.com/edr-platform/sigma-engine/pkg/rules"
	"github.com/jackc/pgx/v5/pgxpool"

	"gopkg.in/yaml.v3"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	kafkaBrokers := flag.String("brokers", "localhost:9092", "Kafka brokers (comma-separated)")
	eventsTopic := flag.String("events-topic", "events-raw", "Kafka topic for events")
	alertsTopic := flag.String("alerts-topic", "alerts", "Kafka topic for alerts")
	consumerGroup := flag.String("group", "sigma-engine-group", "Kafka consumer group")
	workers := flag.Int("workers", 4, "Number of detection workers")
	flag.Parse()

	// Environment variable overrides (docker-compose sets these, not CLI flags)
	if v := os.Getenv("KAFKA_BROKERS"); v != "" {
		*kafkaBrokers = v
	}
	if v := os.Getenv("KAFKA_CONSUMER_TOPIC"); v != "" {
		*eventsTopic = v
	}
	if v := os.Getenv("KAFKA_PRODUCER_TOPIC"); v != "" {
		*alertsTopic = v
	}
	if v := os.Getenv("KAFKA_CONSUMER_GROUP"); v != "" {
		*consumerGroup = v
	}

	// Load base configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger.SetLevel(cfg.Output.LogLevel)
	logger.Info("==========================================")
	logger.Info("Sigma Detection Engine - Kafka Mode")
	logger.Info("==========================================")
	logger.Infof("Brokers: %s | Events: %s | Alerts: %s | Group: %s",
		*kafkaBrokers, *eventsTopic, *alertsTopic, *consumerGroup)
	logger.Infof("Workers: %d | Rules: %s", *workers, cfg.Rules.RulesDirectory)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Shutdown signal received, gracefully shutting down...")
		cancel()
	}()

	// Initialize caches
	fieldCache, err := cache.NewFieldResolutionCache(cfg.Detection.CacheSize)
	if err != nil {
		logger.Fatalf("Failed to create field cache: %v", err)
	}

	regexCache, err := cache.NewRegexCache(cfg.Detection.CacheSize)
	if err != nil {
		logger.Fatalf("Failed to create regex cache: %v", err)
	}

	// Initialize detection engine components
	fieldMapper := mapping.NewFieldMapper(fieldCache)
	modifierEngine := detection.NewModifierRegistry(regexCache)
	quality := detection.QualityConfig{
		MinConfidence:           cfg.Detection.MinConfidence,
		EnableFilters:           cfg.Detection.FiltersEnabled(),
		EnableContextValidation: cfg.Detection.ContextValidationEnabled(),
		Filtering: detection.FilteringConfig{
			Enabled:                    cfg.Filtering.FilteringEnabled(),
			WhitelistedProcesses:       cfg.Filtering.WhitelistedProcesses,
			WhitelistedUsers:           cfg.Filtering.WhitelistedUsers,
			WhitelistedParentProcesses: cfg.Filtering.WhitelistedParentProcesses,
		},
		RuleQuality: detection.RuleQualityConfig{
			MinLevel:         cfg.Rules.MinLevel,
			AllowedStatus:    cfg.Rules.AllowedStatus,
			SkipExperimental: cfg.Rules.SkipExperimentalEnabled(),
		},
	}
	detectionEngine := detection.NewSigmaDetectionEngine(fieldMapper, modifierEngine, fieldCache, quality)

	// Load rules
	logger.Info("Loading Sigma rules...")
	ruleIndex, err := loadRules(ctx, cfg)
	if err != nil {
		logger.Fatalf("Failed to load rules: %v", err)
	}
	if err := detectionEngine.LoadRules(ruleIndex.Rules); err != nil {
		logger.Fatalf("Failed to load rules into detection engine: %v", err)
	}
	logger.Infof("Loaded %d rules", len(ruleIndex.Rules))

	// Configure Kafka
	consumerConfig := infraKafka.ConsumerConfig{
		Brokers:        []string{*kafkaBrokers},
		Topic:          *eventsTopic,
		GroupID:        *consumerGroup,
		MinBytes:       1,
		MaxBytes:       10e6,
		MaxWait:        5 * time.Second,
		CommitInterval: 1 * time.Second,
		StartOffset:    -1, // Latest
	}

	producerConfig := infraKafka.ProducerConfig{
		Brokers:      []string{*kafkaBrokers},
		Topic:        *alertsTopic,
		BatchSize:    50,
		BatchTimeout: 100 * time.Millisecond,
		MaxRetries:   3,
		RequiredAcks: -1, // All
		Compression:  "snappy",
	}

	eventLoopConfig := infraKafka.EventLoopConfig{
		Workers:         *workers,
		EventBuffer:     1000,
		AlertBuffer:     500,
		StatsInterval:   30 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}

	// Create Kafka consumer
	consumer, err := infraKafka.NewEventConsumer(consumerConfig, eventLoopConfig.EventBuffer)
	if err != nil {
		logger.Warnf("Kafka consumer unavailable — detection pipeline disabled: %v", err)
	}

	// Create Kafka producer
	var producer *infraKafka.AlertProducer
	if consumer != nil {
		producer, err = infraKafka.NewAlertProducer(producerConfig, eventLoopConfig.AlertBuffer)
		if err != nil {
			logger.Warnf("Kafka producer unavailable — alert publishing disabled: %v", err)
		}
	}

	// Create alert generator
	alertGenerator := alert.NewAlertGenerator()

	// Start REST API server (serves /health, /api/v1/sigma/*, /metrics)
	apiPort := 8080
	if p := os.Getenv("API_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			apiPort = v
		}
	}

	apiCfg := handlers.DefaultServerConfig()
	apiCfg.Address = ":" + strconv.Itoa(apiPort)

	var apiServer *handlers.Server
	var ruleRepo database.RuleRepository
	var alertRepo database.AlertRepository
	var auditLogger *database.AuditLogger

	dbCfg := database.LoadFromEnv()
	dbPool, dbErr := database.NewPool(ctx, dbCfg)
	if dbErr != nil {
		logger.Warnf("Database unavailable — REST API will serve health/metrics only: %v", dbErr)
	} else {
		// Run database migrations (creates sigma_alerts + sigma_rules tables if missing)
		if err := database.RunMigrations(ctx, dbPool.Pool()); err != nil {
			logger.Fatalf("Failed to run database migrations: %v", err)
		}

		ruleRepo = database.NewPostgresRuleRepository(dbPool.Pool())
		alertRepo = database.NewPostgresAlertRepository(dbPool.Pool())
		auditLogger = database.NewAuditLogger(dbPool.Pool())
		defer dbPool.Close()

		// Auto-seed rules from disk into the database (idempotent UPSERT)
		if ruleIndex != nil && len(ruleIndex.Rules) > 0 {
			seedRulesToDB(ctx, dbPool.Pool(), ruleIndex)
		}
	}
	apiServer = handlers.NewServer(apiCfg, ruleRepo, alertRepo, auditLogger, cfg.RiskScoring.RiskLevels)

	automationNotifier := automation.NewNotificationManager()
	automationPlaybooks := automation.NewPlaybookManager(automationNotifier)
	automationEscalations := automation.NewEscalationManager(automationNotifier)
	apiServer.WireAutomationAPI(automationNotifier, automationPlaybooks, automationEscalations)
	automationEscalations.StartBackgroundChecker(ctx, time.Minute)
	logger.Info("Sigma automation API and in-process playbook/escalation managers enabled")

	// Alert correlation (Kafka EventLoop + REST API); optional PostgreSQL edge persistence + cache warm-start.
	corrMgr := analytics.NewCorrelationManager()
	if dbPool != nil {
		corrRepo := database.NewCorrelationRepository(dbPool.Pool())
		corrMgr.SetPersistence(analytics.NewPostgresEdgePersistence(corrRepo))
		if err := corrMgr.Bootstrap(ctx); err != nil {
			logger.Warnf("Correlation bootstrap: %v", err)
		}
	}
	apiServer.WireCorrelationAPI(corrMgr)
	go func() {
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			logger.Warnf("REST API server error: %v", err)
		}
	}()

	// ── Redis / Lineage Cache + Risk Scoring Setup ────────────────────────────
	// Attempt to connect to Redis for the Context-Aware Lineage Cache and
	// Temporal Burst Tracker. If Redis is unavailable the engine degrades:
	//   - LineageCache → NoopLineageCache (no ancestry context)
	//   - BurstTracker → InMemoryBurstTracker (per-instance burst only)
	//   - RiskScorer   → still runs, but with reduced context info
	var lineageCache cache.LineageCache
	redisCfg := cache.RedisConfigFromEnv()
	redisClient, redisErr := cache.NewRedisClient(redisCfg)
	if redisErr != nil {
		logger.Warnf("Redis unavailable — lineage cache disabled (context-aware scoring will be limited): %v", redisErr)
		lineageCache = cache.NewNoopLineageCache()
	} else {
		lineageCache = cache.NewRedisLineageCache(redisClient)
		defer redisClient.Close()
		logger.Info("Process lineage cache initialised (Redis)")
	}

	// BurstTracker: prefer Redis (shared across pods), fallback to in-memory.
	var burstTracker scoring.BurstTracker
	burstTTL := time.Duration(cfg.RiskScoring.Burst.WindowSec) * time.Second
	if burstTTL <= 0 {
		burstTTL = 5 * time.Minute
	}
	if redisErr == nil {
		burstTracker = scoring.NewRedisBurstTrackerWithTTL(redisClient.Client(), burstTTL)
		logger.Info("Burst tracker initialised (Redis)")
	} else {
		burstTracker = scoring.NewInMemoryBurstTracker(burstTTL)
		logger.Warn("Burst tracker using in-memory fallback (not shared across pods)")
	}

	// BaselineRepository + Cache: requires PostgreSQL (graceful noop when unavailable).
	// The BaselineCache adds a 30-min in-process TTL layer to avoid DB hits per alert.
	var baselineProvider baselines.BaselineProvider
	var baselineAggregator *baselines.BaselineAggregator
	if dbPool != nil {
		baselineRepo := baselines.NewPostgresBaselineRepository(dbPool.Pool())
		baselineProvider = baselines.NewBaselineCache(baselineRepo, 0) // 0 → default 30-min TTL
		baselineAggregator = baselines.NewBaselineAggregator(baselineRepo, 0, 0)
		baselineAggregator.Start(ctx)
		logger.Info("Behavioral baseline aggregator started (UEBA active)")
	} else {
		baselineProvider = baselines.NoopBaselineProvider{}
		logger.Warn("Database unavailable — UEBA baseline scoring disabled")
	}

	// RiskScorer: always constructed — uses the available lineage + burst + baseline impls.
	// All scoring constants are centrally controlled via cfg.RiskScoring (config.yaml).
	riskScorer := scoring.NewDefaultRiskScorerWithConfig(lineageCache, burstTracker, baselineProvider, cfg.RiskScoring)
	if dbPool != nil {
		riskScorer.SetContextPolicyProvider(scoring.NewPostgresContextPolicyProviderWithConfig(
			dbPool.Pool(),
			30*time.Second,
			cfg.RiskScoring.ContextPolicy,
		))
		logger.Info("Context policy provider enabled (hybrid user/device/network factors)")
	}
	logger.Info("RiskScorer initialised — context-aware scoring + UEBA active")
	// ─────────────────────────────────────────────────────────────────────────

	// Create and start event loop (only when Kafka is available)
	var eventLoop *infraKafka.EventLoop
	var alertWriter *database.AlertWriter

	if consumer != nil && producer != nil {
		eventLoop = infraKafka.NewEventLoop(consumer, producer, detectionEngine, alertGenerator, eventLoopConfig)

		// Inject lineage cache — enables process ancestry hydration in processOneEvent.
		// This must be set BEFORE eventLoop.Start() to avoid a race between
		// the worker goroutines and the SetLineageCache call.
		eventLoop.SetLineageCache(lineageCache)

		// Inject RiskScorer — computes context-aware score after every alert is generated.
		// Must be set BEFORE Start() for the same race-condition reason.
		eventLoop.SetRiskScorer(riskScorer)

		// Inject CorrelationManager — time-decayed edges for same-rule / time-window chains.
		eventLoop.SetCorrelationManager(corrMgr)

		// Inject BaselineAggregator — records process events for UEBA behavioral profiling.
		if baselineAggregator != nil {
			eventLoop.SetBaselineAggregator(baselineAggregator)
		}

		eventLoop.SetPlaybookManager(automationPlaybooks)
		eventLoop.SetEscalationManager(automationEscalations)

		// Inject AlertWriter for database persistence (Kafka → PostgreSQL bridge)
		if alertRepo != nil {
			writerConfig := database.DefaultAlertWriterConfig()
			alertWriter = database.NewAlertWriter(alertRepo, writerConfig)
			// Wire real-time WebSocket fan-out directly to persisted alerts so the
			// dashboard live stream reflects newly generated alerts.
			if apiServer != nil && apiServer.WebSocketServer() != nil {
				alertWriter.SetOnAlertPersisted(func(a *database.Alert) {
					apiServer.WebSocketServer().BroadcastAlert(a)
				})
			}
			if err := alertWriter.Start(ctx); err != nil {
				logger.Warnf("Failed to start alert writer: %v", err)
			} else {
				eventLoop.SetAlertWriter(alertWriter)
				logger.Info("Alert writer started — alerts will be persisted to PostgreSQL")
			}
		}

		logger.Info("Starting Kafka event loop...")
		if err := eventLoop.Start(ctx); err != nil {
			logger.Warnf("Failed to start event loop (detection pipeline disabled): %v", err)
			eventLoop = nil
		}

		// Inject live event loop metrics into the REST API stats handler
		if apiServer != nil && eventLoop != nil {
			apiServer.SetPerformanceMetrics(eventLoop)
			logger.Info("Performance metrics provider injected — stats API now returns live data")
		}
	} else {
		logger.Warn("Kafka unavailable — detection pipeline disabled. REST API will serve DB queries only.")
	}

	// Wait for shutdown signal
	<-ctx.Done()

	// Shutdown REST API server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if apiServer != nil {
		_ = apiServer.Shutdown(shutdownCtx)
	}

	// Graceful shutdown
	if eventLoop != nil {
		logger.Info("Shutting down event loop...")
		if err := eventLoop.Stop(); err != nil {
			logger.Errorf("Error stopping event loop: %v", err)
		}
	}

	// Stop alert writer (flush pending DB writes)
	if alertWriter != nil {
		if err := alertWriter.Stop(); err != nil {
			logger.Errorf("Error stopping alert writer: %v", err)
		}
	}

	logger.Info("Sigma Engine (Kafka mode) shutdown complete")
}

// loadRules loads Sigma rules (reused from sigma-engine-live)
func loadRules(ctx context.Context, cfg *config.Config) (*rules.RuleIndex, error) {
	loader := rules.NewRuleLoader(false)

	if len(cfg.Rules.ProductWhitelist) > 0 {
		loader.SetProductWhitelist(cfg.Rules.ProductWhitelist)
	}
	if cfg.Rules.ParallelWorkers > 0 {
		loader.SetParallelWorkers(cfg.Rules.ParallelWorkers)
	}
	// Apply config-driven quality filter (min_level, allowed_status, skip_experimental)
	loader.SetQualityFilter(&rules.QualityFilter{
		MinLevel:         cfg.Rules.MinLevel,
		AllowedStatus:    cfg.Rules.AllowedStatus,
		SkipExperimental: cfg.Rules.SkipExperimentalEnabled(),
	})

	// Try cache first
	if cfg.Rules.CacheFile != "" {
		maxAge := time.Duration(cfg.Rules.CacheMaxAgeHours) * time.Hour
		fingerprint := ""
		if cached, err := rulecache.LoadRulesFromCache(cfg.Rules.CacheFile, maxAge, fingerprint); err == nil {
			indexer := rules.NewRuleIndexer()
			indexer.BuildIndex(cached)
			logger.Infof("Loaded %d rules from cache", len(cached))
			return &rules.RuleIndex{Rules: cached, Indexer: indexer, LoadedAt: time.Now()}, nil
		}
	}

	// Load from directory
	ruleIndex, err := loader.LoadRules(ctx, cfg.Rules.RulesDirectory)
	if err != nil {
		return nil, err
	}

	// Save cache
	if cfg.Rules.CacheFile != "" {
		if err := rulecache.SaveRulesToCache(ruleIndex.Rules, cfg.Rules.CacheFile, ""); err != nil {
			logger.Warnf("Failed to save rule cache: %v", err)
		}
	}

	return ruleIndex, nil
}

// seedRulesToDB converts loaded Sigma rules from disk and upserts them into
// the PostgreSQL sigma_rules table so the dashboard can query them.
// Uses individual UPSERT queries for reliability (pgx SendBatch aborts on first error).
func seedRulesToDB(ctx context.Context, pool *pgxpool.Pool, ruleIndex *rules.RuleIndex) {
	logger.Infof("Seeding %d rules into database...", len(ruleIndex.Rules))

	const upsertSQL = `
		INSERT INTO sigma_rules (
			id, title, description, author, content, enabled, status,
			product, category, service, severity,
			mitre_tactics, mitre_techniques, tags, "references",
			version, source
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			content = EXCLUDED.content,
			severity = EXCLUDED.severity,
			product = EXCLUDED.product,
			category = EXCLUDED.category,
			service = EXCLUDED.service,
			mitre_tactics = EXCLUDED.mitre_tactics,
			mitre_techniques = EXCLUDED.mitre_techniques,
			tags = EXCLUDED.tags`

	var inserted int64
	var errCount int64
	firstErr := ""

	for _, sr := range ruleIndex.Rules {
		if sr.ID == "" || sr.Title == "" {
			continue
		}

		dbRule := domainRuleToDBRule(sr)
		if dbRule == nil {
			continue
		}

		_, err := pool.Exec(ctx, upsertSQL,
			dbRule.ID, dbRule.Title, dbRule.Description, dbRule.Author, dbRule.Content,
			dbRule.Enabled, dbRule.Status,
			dbRule.Product, dbRule.Category, dbRule.Service, dbRule.Severity,
			dbRule.MitreTactics, dbRule.MitreTechniques, dbRule.Tags, dbRule.References,
			dbRule.Version, dbRule.Source,
		)
		if err != nil {
			if atomic.AddInt64(&errCount, 1) == 1 {
				firstErr = fmt.Sprintf("%s (%s): %v", dbRule.ID, dbRule.Title, err)
			}
			continue
		}
		atomic.AddInt64(&inserted, 1)
	}

	if errCount > 0 {
		logger.Warnf("Seed errors: %d failures. First: %s", errCount, firstErr)
	}
	logger.Infof("✅ Seeded %d/%d rules into database", inserted, len(ruleIndex.Rules))
}

// domainRuleToDBRule converts a domain.SigmaRule to a database.Rule.
func domainRuleToDBRule(sr *domain.SigmaRule) *database.Rule {
	// Re-serialize to YAML for the content column
	content, err := yaml.Marshal(sr)
	if err != nil {
		content = []byte(sr.Title) // fallback
	}

	// Map severity: domain uses "level" (e.g., "high"), DB uses "severity"
	severity := strings.ToLower(sr.Level)
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "informational": true,
	}
	if !validSeverities[severity] {
		severity = "medium" // default
	}

	// Map status
	status := strings.ToLower(sr.Status)
	validStatuses := map[string]bool{
		"stable": true, "test": true, "experimental": true, "deprecated": true,
	}
	if !validStatuses[status] {
		status = "stable"
	}

	// Extract product/category/service from logsource
	product := "windows"
	if sr.LogSource.Product != nil {
		product = *sr.LogSource.Product
	}
	category := ""
	if sr.LogSource.Category != nil {
		category = *sr.LogSource.Category
	}
	service := ""
	if sr.LogSource.Service != nil {
		service = *sr.LogSource.Service
	}

	// Extract MITRE tactics and techniques from tags
	var tactics, techniques []string
	for _, tag := range sr.Tags {
		tagLower := strings.ToLower(tag)
		if strings.HasPrefix(tagLower, "attack.t") {
			// Technique: attack.t1059.001 → T1059.001
			parts := strings.SplitN(tag, ".", 2)
			if len(parts) == 2 {
				techniques = append(techniques, strings.ToUpper(parts[1]))
			}
		} else if strings.HasPrefix(tagLower, "attack.") {
			// Tactic: attack.execution → execution
			parts := strings.SplitN(tag, ".", 2)
			if len(parts) == 2 {
				tactics = append(tactics, parts[1])
			}
		}
	}

	return &database.Rule{
		ID:              sr.ID,
		Title:           sr.Title,
		Description:     sr.Description,
		Author:          sr.Author,
		Content:         string(content),
		Enabled:         true,
		Status:          status,
		Product:         product,
		Category:        category,
		Service:         service,
		Severity:        severity,
		MitreTactics:    tactics,
		MitreTechniques: techniques,
		Tags:            sr.Tags,
		References:      sr.References,
		FalsePositives:  sr.FalsePositives,
		Version:         1,
		Source:          "official",
	}
}
