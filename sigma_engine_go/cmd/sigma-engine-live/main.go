package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/alert"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	appmonitoring "github.com/edr-platform/sigma-engine/internal/application/monitoring"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/automation"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/config"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	filemonitoring "github.com/edr-platform/sigma-engine/internal/infrastructure/monitoring"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/output"
	rulecache "github.com/edr-platform/sigma-engine/pkg/rules"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("Configuration validation failed: %v", err)
	}

	// Initialize logger with configured level
	logger.SetLevel(cfg.Output.LogLevel)
	logger.Info("==========================================")
	logger.Info("Sigma Detection Engine - Live Monitoring")
	logger.Info("==========================================")
	logger.Infof("Config: %s | Watch: %s | Rules: %s | Output: %s",
		*configPath,
		cfg.FileMonitoring.WatchDirectory,
		cfg.Rules.RulesDirectory,
		cfg.Output.OutputFile)
	logger.Infof("Workers: %d | Cache: %d | Min Confidence: %.2f",
		cfg.Detection.Workers,
		cfg.Detection.CacheSize,
		cfg.Detection.MinConfidence)

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

	// Initialize caches with configured size
	fieldCache, err := cache.NewFieldResolutionCache(cfg.Detection.CacheSize)
	if err != nil {
		logger.Fatalf("Failed to create field cache: %v", err)
	}

	regexCache, err := cache.NewRegexCache(cfg.Detection.CacheSize)
	if err != nil {
		logger.Fatalf("Failed to create regex cache: %v", err)
	}

	// Initialize components
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

	// Summary already logged by loader

	if err := detectionEngine.LoadRules(ruleIndex.Rules); err != nil {
		logger.Fatalf("Failed to load rules into detection engine: %v", err)
	}

	// Initialize monitoring components with configured values
	eventCounter := appmonitoring.NewEventCounter(
		cfg.EventCounting.WindowSize(),
		cfg.EventCounting.AlertThreshold,
		cfg.EventCounting.RateThresholdPerMinute,
	)

	alertEnricher := appmonitoring.NewAlertEnricher(
		eventCounter,
		cfg.Escalation.CountThreshold,
		cfg.Escalation.RateThresholdPerMinute,
		cfg.Escalation.EnableCriticalEscalation,
	)

	// Initialize file monitor with configured values
	fileMonitor, err := filemonitoring.NewFileMonitor(
		cfg.FileMonitoring.WatchDirectory,
		cfg.FileMonitoring.FilePattern,
		cfg.FileMonitoring.PollInterval(),
		int64(cfg.FileMonitoring.MaxFileSizeGB),
		cfg.FileMonitoring.CheckpointFile,
		cfg.FileMonitoring.CheckpointInterval(),
	)
	if err != nil {
		logger.Fatalf("Failed to create file monitor: %v", err)
	}

	// Initialize output with configured file path
	outputManager := output.NewOutputManager()

	// Use EnhancedJSONLOutput for enhanced alerts
	enhancedOutput, err := output.NewEnhancedJSONLOutput(cfg.Output.OutputFile)
	if err != nil {
		logger.Fatalf("Failed to create output file: %v", err)
	}
	defer func() {
		if err := enhancedOutput.Close(); err != nil {
			logger.Errorf("Failed to close output file: %v", err)
		}
	}()
	outputManager.RegisterOutput("enhanced_jsonl", enhancedOutput)

	automationNotifier := automation.NewNotificationManager()
	automationPlaybooks := automation.NewPlaybookManager(automationNotifier)
	automationEscalations := automation.NewEscalationManager(automationNotifier)
	automationEscalations.StartBackgroundChecker(ctx, time.Minute)
	logger.Info("Live engine: playbook + escalation automation enabled (in-process)")

	// Start file monitor
	if err := fileMonitor.Start(); err != nil {
		logger.Fatalf("Failed to start file monitor: %v", err)
	}
	defer func() {
		fileMonitor.Stop()
		logger.Info("File monitor stopped")
	}()

	// Start event counter cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				eventCounter.Cleanup()
			}
		}
	}()

	// Start statistics reporting
	var totalAlerts uint64
	var alertsMu sync.Mutex
	go reportStatistics(ctx, fileMonitor, eventCounter, outputManager, &totalAlerts, &alertsMu)

	// Main processing loop
	logger.Info("Starting live monitoring...")
	processEvents(ctx, fileMonitor, detectionEngine, alertEnricher, outputManager, cfg, &totalAlerts, &alertsMu, automationPlaybooks, automationEscalations)

	logger.Info("Application shutdown complete")
}

// loadRules loads Sigma rules from directory with product whitelist filtering and caching.
func loadRules(ctx context.Context, cfg *config.Config) (*rules.RuleIndex, error) {
	loader := rules.NewRuleLoader(false)

	// Product whitelist filtering
	if len(cfg.Rules.ProductWhitelist) > 0 {
		loader.SetProductWhitelist(cfg.Rules.ProductWhitelist)
	}

	// Parallel parsing workers
	if cfg.Rules.ParallelWorkers > 0 {
		loader.SetParallelWorkers(cfg.Rules.ParallelWorkers)
	}

	// Cache fingerprint: changes when rule-selection configuration changes
	fingerprint := fmt.Sprintf(
		"products=%v|minLevel=%s|status=%v|skipExp=%v",
		cfg.Rules.ProductWhitelist,
		cfg.Rules.MinLevel,
		cfg.Rules.AllowedStatus,
		cfg.Rules.SkipExperimentalEnabled(),
	)

	// Try loading from cache first
	if cfg.Rules.CacheFile != "" {
		maxAge := time.Duration(cfg.Rules.CacheMaxAgeHours) * time.Hour
		if cached, err := rulecache.LoadRulesFromCache(cfg.Rules.CacheFile, maxAge, fingerprint); err == nil {
			indexer := rules.NewRuleIndexer()
			indexer.BuildIndex(cached)
			logger.Infof("Loaded %d rules from cache (%s)", len(cached), cfg.Rules.CacheFile)
			return &rules.RuleIndex{
				Rules:    cached,
				Indexer:  indexer,
				LoadedAt: time.Now(),
				Errors:   nil,
			}, nil
		} else {
			logger.Debugf("Rule cache miss: %v", err)
		}
	}

	// Cache miss -> load from directory
	ruleIndex, err := loader.LoadRules(ctx, cfg.Rules.RulesDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}
	if len(ruleIndex.Rules) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", cfg.Rules.RulesDirectory)
	}

	// Save cache (best-effort)
	if cfg.Rules.CacheFile != "" {
		if err := rulecache.SaveRulesToCache(ruleIndex.Rules, cfg.Rules.CacheFile, fingerprint); err != nil {
			logger.Warnf("Failed to save rule cache: %v", err)
		} else {
			logger.Infof("Saved rule cache: %s", cfg.Rules.CacheFile)
		}
	}

	// Summary already logged by loader
	return ruleIndex, nil
}

func runPlaybookAutomation(ctx context.Context, playbooks *automation.PlaybookManager, escalations *automation.EscalationManager, a *domain.Alert) {
	if a == nil {
		return
	}
	if escalations != nil {
		escalations.TrackAlert(a)
	}
	if playbooks != nil {
		playbooks.ExecuteForAlert(ctx, a)
	}
}

// processEvents processes events from the file monitor using ATOMIC EVENT AGGREGATION.
// Key change: Instead of 1 event → N alerts (one per matched rule), we now produce
// 1 event → 1 aggregated alert (combining all matched rules).
// This dramatically reduces alert fatigue while preserving detection fidelity.
func processEvents(
	ctx context.Context,
	fileMonitor *filemonitoring.FileMonitor,
	detectionEngine *detection.SigmaDetectionEngine,
	alertEnricher *appmonitoring.AlertEnricher,
	outputManager *output.OutputManager,
	cfg *config.Config,
	totalAlerts *uint64,
	alertsMu *sync.Mutex,
	playbooks *automation.PlaybookManager,
	escalations *automation.EscalationManager,
) {
	eventChan := fileMonitor.Events()
	errorChan := fileMonitor.Errors()
	alertGenerator := alert.NewAlertGenerator()

	// Alert escalation log throttling: track per-rule log counts
	escalationLogCounts := make(map[string]int) // ruleID -> log count
	var escalationLogMu sync.Mutex
	const escalationLogInterval = 100 // Log every 100th alert for same rule

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-eventChan:
			if !ok {
				return
			}

			// Extract source file from event if available
			sourceFile := ""
			if filePath, ok := event.GetField("source_file"); ok {
				if str, ok := filePath.(string); ok {
					sourceFile = str
				}
			}
			// Fallback: use watch directory + normalized_logs.jsonl
			if sourceFile == "" {
				sourceFile = filepath.Join(cfg.FileMonitoring.WatchDirectory, "normalized_logs.jsonl")
			}

			// =================================================================
			// ATOMIC EVENT AGGREGATION: Use DetectAggregated instead of Detect
			// This collects ALL rule matches for a single event before alerting.
			// =================================================================
			matchResult := detectionEngine.DetectAggregated(event)

			// Skip if no rules matched
			if !matchResult.HasMatches() {
				continue
			}

			// Generate ONE aggregated alert from ALL matches
			baseAlert := alertGenerator.GenerateAggregatedAlert(matchResult)
			if baseAlert == nil {
				continue
			}

			// Log multi-match events for visibility (useful for tuning)
			if matchResult.MatchCount() > 1 {
				// Removed verbose debug log - too noisy
			}

			// Enrich alert with event statistics
			enhancedAlert := alertEnricher.EnrichAlert(baseAlert, event, sourceFile)
			if enhancedAlert == nil {
				// Fallback to base alert if enrichment fails
				if err := outputManager.WriteAlert(baseAlert); err != nil {
					logger.Warnf("Failed to write alert: %v", err)
				} else {
					runPlaybookAutomation(ctx, playbooks, escalations, baseAlert)
				}
				continue
			}

			// Write enhanced alert using enhanced output
			alertWritten := false
			if writer, ok := outputManager.GetOutput("enhanced_jsonl"); ok {
				if enhancedOutput, ok := writer.(*output.EnhancedJSONLOutput); ok {
					if err := enhancedOutput.WriteEnhancedAlert(enhancedAlert); err != nil {
						logger.Warnf("Failed to write enhanced alert: %v", err)
					} else {
						alertWritten = true
					}
				} else {
					// Fallback to regular alert output
					if err := outputManager.WriteAlert(baseAlert); err != nil {
						logger.Warnf("Failed to write alert: %v", err)
					} else {
						alertWritten = true
					}
				}
			} else {
				// Fallback to regular alert output
				if err := outputManager.WriteAlert(baseAlert); err != nil {
					logger.Warnf("Failed to write alert: %v", err)
				} else {
					alertWritten = true
				}
			}

			// Increment alert counter if successfully written
			// Note: Now this is 1 per event (not 1 per rule match)
			if alertWritten {
				runPlaybookAutomation(ctx, playbooks, escalations, baseAlert)
				alertsMu.Lock()
				(*totalAlerts)++
				alertsMu.Unlock()
			}

			// Log escalation with throttling (to prevent console spam)
			if enhancedAlert.ShouldEscalate {
				escalationLogMu.Lock()
				count := escalationLogCounts[enhancedAlert.RuleID]
				count++
				escalationLogCounts[enhancedAlert.RuleID] = count
				shouldLog := count == 1 || count%escalationLogInterval == 0
				escalationLogMu.Unlock()

				if shouldLog {
					// Include match count in escalation log for visibility
					matchInfo := ""
					if baseAlert.MatchCount > 1 {
						matchInfo = fmt.Sprintf(" [%d rules matched]", baseAlert.MatchCount)
					}

					if count == 1 {
						// Log first escalation immediately
						logger.Warnf("ALERT ESCALATION: %s - %s (Count: %d, Rate: %.2f/min, Trend: %s)%s",
							enhancedAlert.RuleTitle,
							enhancedAlert.EscalationReason,
							enhancedAlert.EventCount,
							enhancedAlert.RatePerMinute,
							enhancedAlert.CountTrend,
							matchInfo,
						)
					} else {
						// Log every Nth escalation
						logger.Warnf("ALERT ESCALATION: %s - %s (Count: %d, Rate: %.2f/min, Trend: %s) [Logged %d/%d]%s",
							enhancedAlert.RuleTitle,
							enhancedAlert.EscalationReason,
							enhancedAlert.EventCount,
							enhancedAlert.RatePerMinute,
							enhancedAlert.CountTrend,
							count,
							count,
							matchInfo,
						)
					}
				}
				// Note: ALL alerts are still written to output file, only console logging is throttled
			}

		case err, ok := <-errorChan:
			if !ok {
				return
			}
			logger.Warnf("File monitor error: %v", err)
		}
	}
}

// getEventIDForLogging returns event ID string for logging purposes.
func getEventIDForLogging(event *domain.LogEvent) string {
	if event != nil && event.EventID != nil {
		return *event.EventID
	}
	return "unknown"
}

// reportStatistics periodically reports statistics.
func reportStatistics(
	ctx context.Context,
	fileMonitor *filemonitoring.FileMonitor,
	eventCounter *appmonitoring.EventCounter,
	outputManager *output.OutputManager,
	totalAlerts *uint64,
	alertsMu *sync.Mutex,
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			monitorStats := fileMonitor.Stats()

			alertsMu.Lock()
			alertCount := *totalAlerts
			alertsMu.Unlock()

			logger.Infof("📊 Stats | Files: %d | Events: %d | Alerts: %d | Errors: %d",
				monitorStats.FilesTracked,
				monitorStats.EventsEmitted,
				alertCount,
				monitorStats.Errors,
			)
		}
	}
}
