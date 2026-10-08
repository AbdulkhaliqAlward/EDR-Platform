package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// AutomationService manages playbook and automation-rule definitions.
//
// Matching alerts to rules, binding alert context and executing playbooks is
// done by the response engine (internal/response), which reads Sigma alerts
// and dispatches real agent commands.
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
	}
}

// GetPlaybookByID retrieves a playbook by ID
func (s *AutomationService) GetPlaybookByID(ctx context.Context, playbookID uuid.UUID) (*models.ResponsePlaybook, error) {
	return s.playbookRepo.GetByID(ctx, playbookID)
}

// CreatePlaybook creates a new playbook
func (s *AutomationService) CreatePlaybook(ctx context.Context, playbook *models.ResponsePlaybook) error {
	return s.playbookRepo.Create(ctx, playbook)
}

// UpdatePlaybook persists an edited playbook (definition, steps, enabled flag).
func (s *AutomationService) UpdatePlaybook(ctx context.Context, playbook *models.ResponsePlaybook) error {
	return s.playbookRepo.Update(ctx, playbook)
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

// GetRuleOptimizations retrieves ML-based rule optimization suggestions
func (s *AutomationService) GetRuleOptimizations(ctx context.Context) ([]RuleOptimization, error) {
	return s.mlOptimizer.SuggestRuleOptimizations(ctx)
}

// RuleOptimization represents a suggested optimization for a rule
type RuleOptimization struct {
	Type           string      `json:"type"`
	RuleID         uuid.UUID   `json:"rule_id"`
	Reason         string      `json:"reason"`
	SuggestedValue interface{} `json:"suggested_value"`
	Confidence     float64     `json:"confidence"`
}
