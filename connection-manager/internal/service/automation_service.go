package service

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// AutomationService provides intelligent automation capabilities for EDR alerts
type AutomationService struct {
	logger              *logrus.Logger
	alertRepo           repository.AlertRepository
	playbookRepo        repository.ResponsePlaybookRepository
	automationRepo      repository.AutomationRuleRepository
	executionRepo       repository.PlaybookExecutionRepository
	commandService      *CommandService
	notificationService *NotificationService
	metricsService      *MetricsService
	mlOptimizer         *MLOptimizer
	cooldownMap         map[uuid.UUID]time.Time
	cooldownMutex       sync.RWMutex
}

// NewAutomationService creates a new automation service instance
func NewAutomationService(
	logger *logrus.Logger,
	alertRepo repository.AlertRepository,
	playbookRepo repository.ResponsePlaybookRepository,
	automationRepo repository.AutomationRuleRepository,
	executionRepo repository.PlaybookExecutionRepository,
	commandService *CommandService,
	notificationService *NotificationService,
	metricsService *MetricsService,
	mlOptimizer *MLOptimizer,
) *AutomationService {
	return &AutomationService{
		logger:              logger,
		alertRepo:           alertRepo,
		playbookRepo:        playbookRepo,
		automationRepo:      automationRepo,
		executionRepo:       executionRepo,
		commandService:      commandService,
		notificationService: notificationService,
		metricsService:      metricsService,
		mlOptimizer:         mlOptimizer,
		cooldownMap:         make(map[uuid.UUID]time.Time),
	}
}

// ProcessAlert handles the main alert processing workflow
func (s *AutomationService) ProcessAlert(ctx context.Context, alert *models.Alert) error {
	startTime := time.Now()

	s.logger.WithFields(logrus.Fields{
		"alert_id":  alert.ID,
		"severity":  alert.Severity,
		"rule_name": alert.RuleName,
		"agent_id":  alert.AgentID,
	}).Info("Starting intelligent alert processing")

	// 1. Find matching automation rules
	rules, err := s.automationRepo.GetMatchingRules(ctx, alert)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get matching automation rules")
		return err
	}

	s.logger.Infof("Found %d matching automation rules", len(rules))

	// 2. Optimize rule priorities using ML
	optimizedRules := s.mlOptimizer.OptimizeRulePriority(rules, alert)

	// 3. Execute automatic rules in parallel
	var wg sync.WaitGroup
	for _, rule := range optimizedRules {
		if rule.AutoExecute && s.shouldExecute(rule, alert) {
			wg.Add(1)
			go func(r *models.AutomationRule) {
				defer wg.Done()
				s.executePlaybookAsync(ctx, r.PlaybookID, alert.ID, r.ID)
			}(rule)
		}
	}

	// 4. Generate intelligent playbook suggestions
	suggestions := s.generateIntelligentSuggestions(alert)
	if err := s.storeSuggestions(ctx, alert.ID, suggestions); err != nil {
		s.logger.WithError(err).Error("Failed to store suggestions")
	}

	// 5. Update metrics
	processingTime := time.Since(startTime)
	s.metricsService.RecordAlertProcessing(alert, len(rules), len(suggestions), processingTime)

	// 6. Send intelligent notifications
	s.notificationService.SendAlertProcessed(alert, len(rules), len(suggestions))

	return nil
}

// shouldExecute checks if a rule should be executed based on conditions
func (s *AutomationService) shouldExecute(rule *models.AutomationRule, alert *models.Alert) bool {
	// Check cooldown period
	if s.isInCooldown(rule.ID, rule.CooldownMinutes) {
		s.logger.Infof("Rule %s is in cooldown period", rule.Name)
		return false
	}

	// Check success rate
	if rule.SuccessRate < 0.5 && rule.LastExecution != nil {
		s.logger.Infof("Rule %s has low success rate (%.2f%%)", rule.Name, rule.SuccessRate*100)
		return false
	}

	// Check advanced conditions
	var conditions map[string]interface{}
	if len(rule.TriggerConditions) > 0 {
		if err := json.Unmarshal(rule.TriggerConditions, &conditions); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal trigger conditions")
			return false
		}
	}
	return s.evaluateAdvancedConditions(conditions, alert)
}

// evaluateAdvancedConditions evaluates complex trigger conditions
func (s *AutomationService) evaluateAdvancedConditions(conditions map[string]interface{}, alert *models.Alert) bool {
	// Check severity. JSON values decode as plain strings, so compare against
	// string(alert.Severity) — comparing to the AlertSeverity type never matches.
	if severities, ok := conditions["severity"].([]interface{}); ok {
		if !contains(severities, string(alert.Severity)) {
			return false
		}
	}

	// Check rule patterns
	if patterns, ok := conditions["rule_patterns"].([]interface{}); ok {
		ruleName := strings.ToLower(alert.RuleName)
		matched := false
		for _, pattern := range patterns {
			p, isStr := pattern.(string)
			if !isStr || p == "" {
				continue
			}
			if strings.Contains(ruleName, strings.ToLower(p)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check minimum risk score (0-100, alerts.risk_score)
	if minRisk, ok := conditions["min_risk_score"].(float64); ok && minRisk > 0 {
		if float64(alert.RiskScore) < minRisk {
			return false
		}
	}

	// Check confidence threshold
	if threshold, ok := conditions["confidence_threshold"].(float64); ok && threshold > 0 {
		if alert.Confidence < threshold {
			return false
		}
	}

	// Check logic operator
	if operator, ok := conditions["logic_operator"].(string); ok && operator == "OR" {
		// For OR logic, any condition match is sufficient
		return true
	}

	return true
}

// generateIntelligentSuggestions creates smart playbook suggestions
func (s *AutomationService) generateIntelligentSuggestions(alert *models.Alert) []models.PlaybookSuggestion {
	var suggestions []models.PlaybookSuggestion

	// Severity-based suggestions
	if alert.Severity == "critical" {
		suggestions = append(suggestions, models.PlaybookSuggestion{
			PlaybookID: uuid.MustParse("malware_immediate_containment"),
			Confidence: 0.95,
			Reason:     "Critical severity alert requires immediate containment",
			MITREMatch: []string{"T1055", "T1059"},
		})
	}

	// Rule name-based suggestions
	ruleName := strings.ToLower(alert.RuleName)
	if strings.Contains(ruleName, "malware") || strings.Contains(ruleName, "trojan") {
		suggestions = append(suggestions, models.PlaybookSuggestion{
			PlaybookID: uuid.MustParse("advanced_malware_analysis"),
			Confidence: 0.85,
			Reason:     "Malware-related behavior detected",
			MITREMatch: []string{"T1055", "T1543"},
		})
	}

	// Risk score-based suggestions
	if alert.RiskScore > 8.0 {
		suggestions = append(suggestions, models.PlaybookSuggestion{
			PlaybookID: uuid.MustParse("comprehensive_system_scan"),
			Confidence: 0.90,
			Reason:     "High-risk agent detected",
			MITREMatch: []string{"T1082", "T1018"},
		})
	}

	// Ransomware-specific suggestions
	if strings.Contains(ruleName, "ransomware") || strings.Contains(ruleName, "encryption") {
		suggestions = append(suggestions, models.PlaybookSuggestion{
			PlaybookID: uuid.MustParse("ransomware_attack_response"),
			Confidence: 0.98,
			Reason:     "Ransomware activity detected",
			MITREMatch: []string{"T1486", "T1059"},
		})
	}

	return suggestions
}

// executePlaybookAsync executes a playbook asynchronously with monitoring
func (s *AutomationService) executePlaybookAsync(ctx context.Context, playbookID, alertID, ruleID uuid.UUID) {
	startTime := time.Now()

	execution := &models.PlaybookExecution{
		AlertID:    alertID,
		PlaybookID: playbookID,
		RuleID:     &ruleID,
		Status:     "running",
		StartedAt:  time.Now(),
	}

	if err := s.executionRepo.Create(ctx, execution); err != nil {
		s.logger.WithError(err).Error("Failed to create execution record")
		return
	}

	// Execute commands with monitoring
	success := s.executePlaybookCommands(ctx, playbookID, alertID, execution.ID)

	// Update results
	executionTime := time.Since(startTime)
	execution.Status = "completed"
	execution.CompletedAt = &time.Time{}
	execution.ExecutionTimeMs = int(executionTime.Milliseconds())

	if !success {
		execution.Status = "failed"
		execution.ErrorMessage = "One or more commands failed"
	}

	s.executionRepo.Update(ctx, execution)

	// Update rule metrics
	s.updateRuleMetrics(ruleID, success, executionTime)

	// Send completion notification
	s.notificationService.SendPlaybookCompleted(execution, success)
}

// executePlaybookCommands executes all commands in a playbook
func (s *AutomationService) executePlaybookCommands(ctx context.Context, playbookID, alertID, executionID uuid.UUID) bool {
	playbook, err := s.playbookRepo.GetByID(ctx, playbookID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get playbook")
		return false
	}

	alert, err := s.alertRepo.GetByID(ctx, alertID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get alert")
		return false
	}

	success := true
	var commands []models.PlaybookCommand
	if err := json.Unmarshal(playbook.Commands, &commands); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal playbook commands")
		return false
	}

	for i, cmd := range commands {
		s.logger.Infof("Executing command %d/%d: %s", i+1, len(commands), cmd.Type)

		result := s.commandService.ExecutePlaybookCommand(ctx, executionID, cmd, alert.AgentID)

		if result.Status == "failed" && cmd.OnFailure == "stop" {
			s.logger.Errorf("Command %s failed, stopping playbook execution", cmd.Type)
			success = false
			break
		}
		if result.Status == "failed" {
			s.logger.Warnf("Command %s failed but continuing", cmd.Type)
		}
	}

	return success
}

// isInCooldown checks if a rule is in cooldown period
func (s *AutomationService) isInCooldown(ruleID uuid.UUID, cooldownMinutes int) bool {
	if cooldownMinutes <= 0 {
		return false
	}

	s.cooldownMutex.RLock()
	defer s.cooldownMutex.RUnlock()

	lastExecution, exists := s.cooldownMap[ruleID]
	if !exists {
		return false
	}

	return time.Since(lastExecution) < time.Duration(cooldownMinutes)*time.Minute
}

// setCooldown sets a cooldown for a rule
func (s *AutomationService) setCooldown(ruleID uuid.UUID) {
	s.cooldownMutex.Lock()
	defer s.cooldownMutex.Unlock()

	s.cooldownMap[ruleID] = time.Now()
}

// updateRuleMetrics updates rule performance metrics
func (s *AutomationService) updateRuleMetrics(ruleID uuid.UUID, success bool, executionTime time.Duration) {
	// Update rule success rate
	rule, err := s.automationRepo.GetByID(context.Background(), ruleID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rule for metrics update")
		return
	}

	// Simple moving average for success rate
	if success {
		rule.SuccessRate = (rule.SuccessRate*0.8 + 0.2) // 80% weight to old, 20% to new success
	} else {
		rule.SuccessRate = (rule.SuccessRate * 0.8) // 80% weight to old, 0% to new failure
	}

	rule.LastExecution = &time.Time{}
	*rule.LastExecution = time.Now()

	s.automationRepo.Update(context.Background(), rule)

	// Set cooldown
	s.setCooldown(ruleID)

	// Record metrics
	s.metricsService.RecordRuleExecution(ruleID, success, executionTime)
}

// storeSuggestions stores playbook suggestions for an alert
func (s *AutomationService) storeSuggestions(ctx context.Context, alertID uuid.UUID, suggestions []models.PlaybookSuggestion) error {
	for _, suggestion := range suggestions {
		suggestion.AlertID = alertID
		suggestion.CreatedAt = time.Now()
		if err := s.executionRepo.CreateSuggestion(ctx, &suggestion); err != nil {
			s.logger.WithError(err).Error("Failed to store suggestion")
			return err
		}
	}
	return nil
}

// GetSuggestions retrieves playbook suggestions for an alert
func (s *AutomationService) GetSuggestions(ctx context.Context, alertID uuid.UUID) ([]models.PlaybookSuggestion, error) {
	return s.executionRepo.GetSuggestions(ctx, alertID)
}

// ExecutePlaybookForAlert manually executes a playbook for a specific alert
func (s *AutomationService) ExecutePlaybookForAlert(ctx context.Context, playbookID, alertID, userID uuid.UUID) (*models.PlaybookExecution, error) {
	execution := &models.PlaybookExecution{
		AlertID:    alertID,
		PlaybookID: playbookID,
		Status:     "running",
		StartedAt:  time.Now(),
		CreatedBy:  &userID,
	}

	if err := s.executionRepo.Create(ctx, execution); err != nil {
		return nil, err
	}

	// Execute asynchronously
	go s.executePlaybookAsync(ctx, playbookID, alertID, uuid.New())

	return execution, nil
}

// GetMatchingRules retrieves rules that match an alert
func (s *AutomationService) GetMatchingRules(ctx context.Context, alert *models.Alert) ([]*models.AutomationRule, error) {
	return s.automationRepo.GetMatchingRules(ctx, alert)
}

// GetPlaybookByID retrieves a playbook by ID
func (s *AutomationService) GetPlaybookByID(ctx context.Context, playbookID uuid.UUID) (*models.ResponsePlaybook, error) {
	return s.playbookRepo.GetByID(ctx, playbookID)
}

// CreatePlaybook creates a new playbook
func (s *AutomationService) CreatePlaybook(ctx context.Context, playbook *models.ResponsePlaybook) error {
	return s.playbookRepo.Create(ctx, playbook)
}

// ListPlaybooks retrieves all playbooks
func (s *AutomationService) ListPlaybooks(ctx context.Context, filter repository.PlaybookFilter) ([]*models.ResponsePlaybook, error) {
	return s.playbookRepo.List(ctx, filter)
}

// ListRules retrieves all automation rules
func (s *AutomationService) ListRules(ctx context.Context) ([]*models.AutomationRule, error) {
	return s.automationRepo.List(ctx)
}

// CreateRule creates a new automation rule
func (s *AutomationService) CreateRule(ctx context.Context, rule *models.AutomationRule) error {
	return s.automationRepo.Create(ctx, rule)
}

// GetRuleByID retrieves an automation rule by ID
func (s *AutomationService) GetRuleByID(ctx context.Context, ruleID uuid.UUID) (*models.AutomationRule, error) {
	return s.automationRepo.GetByID(ctx, ruleID)
}

// UpdateRule updates an automation rule
func (s *AutomationService) UpdateRule(ctx context.Context, rule *models.AutomationRule) error {
	return s.automationRepo.Update(ctx, rule)
}

// DeleteRule deletes an automation rule
func (s *AutomationService) DeleteRule(ctx context.Context, ruleID uuid.UUID) error {
	return s.automationRepo.Delete(ctx, ruleID)
}

// DeletePlaybook deletes a playbook
func (s *AutomationService) DeletePlaybook(ctx context.Context, playbookID uuid.UUID) error {
	return s.playbookRepo.Delete(ctx, playbookID)
}

// GetAlertByID retrieves an alert by ID
func (s *AutomationService) GetAlertByID(ctx context.Context, alertID uuid.UUID) (*models.Alert, error) {
	return s.alertRepo.GetByID(ctx, alertID)
}

// GetRuleOptimizations retrieves ML-based rule optimization suggestions
func (s *AutomationService) GetRuleOptimizations(ctx context.Context) ([]RuleOptimization, error) {
	return s.mlOptimizer.SuggestRuleOptimizations(ctx)
}

// Helper function to check if slice contains element
func contains(slice []interface{}, item interface{}) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RuleOptimization represents a suggested optimization for a rule
type RuleOptimization struct {
	Type           string      `json:"type"`
	RuleID         uuid.UUID   `json:"rule_id"`
	Reason         string      `json:"reason"`
	SuggestedValue interface{} `json:"suggested_value"`
	Confidence     float64     `json:"confidence"`
}
