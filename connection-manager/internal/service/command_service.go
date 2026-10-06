package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// CommandService handles command execution for playbooks
type CommandService struct {
	logger        *logrus.Logger
	commandRepo   repository.CommandRepository
	executionRepo repository.PlaybookExecutionRepository
	metricsRepo   repository.AutomationMetricsRepository
}

// NewCommandService creates a new command service instance
func NewCommandService(
	logger *logrus.Logger,
	commandRepo repository.CommandRepository,
	executionRepo repository.PlaybookExecutionRepository,
	metricsRepo repository.AutomationMetricsRepository,
) *CommandService {
	return &CommandService{
		logger:        logger,
		commandRepo:   commandRepo,
		executionRepo: executionRepo,
		metricsRepo:   metricsRepo,
	}
}

// ExecutePlaybookCommand executes a command from a playbook
func (s *CommandService) ExecutePlaybookCommand(ctx context.Context, executionID uuid.UUID, cmd models.PlaybookCommand, agentID uuid.UUID) *CommandResult {
	// Inject the playbook-context marker into run_cmd parameters so the agent
	// grants this command access to the extended playbookAllowedCommands
	// whitelist (which includes powershell -Command and other safe ops).
	// This is safe because playbooks are server-authored and RBAC-protected.
	params := cmd.Parameters
	if params == nil {
		params = make(map[string]interface{})
	}
	// Mark this as a server-authored, RBAC-protected command. For run_cmd the
	// "library" authorization tier unlocks the extended playbookAllowedCommands
	// whitelist (powershell -Command, mountvol, etc.). This marker is set
	// server-side only; the manual API path strips any client-supplied value.
	params["authz_tier"] = "library"
	params["from_playbook"] = "true" // legacy marker for older agents

	// Convert playbook command to system command
	command := &models.Command{
		AgentID:        agentID,
		CommandType:    models.CommandType(cmd.Type),
		Parameters:     params,
		TimeoutSeconds: cmd.Timeout,
		Status:         models.CommandStatusPending,
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(time.Duration(cmd.Timeout) * time.Second),
		Metadata: map[string]interface{}{
			"playbook_execution_id": executionID,
			"description":           cmd.Description,
		},
	}
	
	// Insert command into queue
	if err := s.commandRepo.Create(ctx, command); err != nil {
		return &CommandResult{
			Status:    "failed",
			Error:     err.Error(),
			CompletedAt: time.Now(),
		}
	}
	
	// Wait for execution result
	result := s.WaitForCommandResult(ctx, command.ID, time.Duration(cmd.Timeout)*time.Second)
	
	// Record metrics
	// TODO: Implement metrics recording when repository method is available
	
	return result
}

// WaitForCommandResult waits for command execution result
func (s *CommandService) WaitForCommandResult(ctx context.Context, commandID uuid.UUID, timeout time.Duration) *CommandResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return &CommandResult{
				Status:    "timeout",
				Error:     "Command execution timeout",
				CompletedAt: time.Now(),
			}
		case <-ticker.C:
			cmd, err := s.commandRepo.GetByID(ctx, commandID)
			if err != nil {
				return &CommandResult{
					Status:    "error",
					Error:     err.Error(),
					CompletedAt: time.Now(),
				}
			}
			
			if cmd.Status == models.CommandStatusCompleted || cmd.Status == models.CommandStatusFailed {
				completedAt := time.Now()
				if cmd.CompletedAt != nil {
					completedAt = *cmd.CompletedAt
				}
				return &CommandResult{
					Status:    string(cmd.Status),
					Result:    cmd.Result,
					Error:     cmd.ErrorMessage,
					CompletedAt: completedAt,
				}
			}
		}
	}
}

// Create creates a new command (for backward compatibility)
func (s *CommandService) Create(ctx context.Context, command *models.Command) error {
	return s.commandRepo.Create(ctx, command)
}

// GetByID retrieves a command by ID (for backward compatibility)
func (s *CommandService) GetByID(ctx context.Context, id uuid.UUID) (*models.Command, error) {
	return s.commandRepo.GetByID(ctx, id)
}

// CommandResult represents the result of command execution
type CommandResult struct {
	Status      string                 `json:"status"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CompletedAt time.Time              `json:"completed_at"`
}
