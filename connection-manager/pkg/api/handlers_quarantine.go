package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// ListAgentQuarantine returns inventoried quarantined files for an endpoint (from telemetry + C2).
func (h *Handlers) ListAgentQuarantine(c echo.Context) error {
	if h.quarantineRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "QUARANTINE_UNAVAILABLE", "Quarantine inventory is not configured")
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID")
	}
	include := strings.EqualFold(c.QueryParam("include_resolved"), "true") || strings.EqualFold(c.QueryParam("all"), "1")
	items, err := h.quarantineRepo.ListByAgent(c.Request().Context(), agentID, include)
	if err != nil {
		h.logger.WithError(err).Warn("[Quarantine] List failed")
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to list quarantine inventory")
	}
	items = capList(c, items)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": items,
		"meta":  responseMeta(c),
	})
}

// QuarantineDecisionRequest is the body for POST .../quarantine/:entryId/decision.
type QuarantineDecisionRequest struct {
	Decision string `json:"decision"` // acknowledge | restore | delete
}

// PostAgentQuarantineDecision applies analyst choice: acknowledge, restore to original path, or delete from quarantine.
func (h *Handlers) PostAgentQuarantineDecision(c echo.Context) error {
	if h.quarantineRepo == nil || h.registry == nil || h.commandRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "QUARANTINE_UNAVAILABLE", "Quarantine or C2 is not configured")
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID")
	}
	entryID, err := uuid.Parse(c.Param("entryId"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ENTRY", "Invalid quarantine entry ID")
	}
	var body QuarantineDecisionRequest
	if err := c.Bind(&body); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON body")
	}
	dec := strings.ToLower(strings.TrimSpace(body.Decision))
	switch dec {
	case "acknowledge", "restore", "delete":
	default:
		return errorResponse(c, http.StatusBadRequest, "INVALID_DECISION", "decision must be acknowledge, restore, or delete")
	}

	row, err := h.quarantineRepo.GetByID(c.Request().Context(), entryID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Quarantine entry not found")
		}
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to load quarantine entry")
	}
	if row.AgentID != agentID {
		return errorResponse(c, http.StatusForbidden, "AGENT_MISMATCH", "Entry does not belong to this agent")
	}
	if row.State == models.QuarantineStateRestored || row.State == models.QuarantineStateDeleted {
		return errorResponse(c, http.StatusConflict, "ALREADY_FINAL", "This entry is already restored or deleted")
	}

	switch dec {
	case "acknowledge":
		if err := h.quarantineRepo.SetState(c.Request().Context(), entryID, models.QuarantineStateAcknowledged); err != nil {
			return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to update state")
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":   "acknowledged",
			"entry_id": entryID.String(),
			"meta":     responseMeta(c),
		})
	case "restore", "delete":
		if !h.registry.IsOnline(agentID.String()) {
			return errorResponse(c, http.StatusNotFound, "AGENT_OFFLINE", "Agent is not online — command cannot be delivered")
		}
		cmdType := "restore_quarantine_file"
		params := map[string]string{
			"quarantine_path": row.QuarantinePath,
			"original_path":   row.OriginalPath,
		}
		if dec == "delete" {
			cmdType = "delete_quarantine_file"
			params = map[string]string{"quarantine_path": row.QuarantinePath}
		}
		meta := map[string]any{
			"quarantine_item_id": entryID.String(),
			"decision":           dec,
		}
		cmdID, err := h.dispatchOneShotC2Command(c.Request().Context(), c, agentID, cmdType, params, meta)
		if err != nil {
			return errorResponse(c, http.StatusConflict, "SEND_FAILED", err.Error())
		}
		return c.JSON(http.StatusAccepted, map[string]interface{}{
			"status":     "command_sent",
			"command_id": cmdID.String(),
			"decision":   dec,
			"meta":       responseMeta(c),
		})
	default:
		return errorResponse(c, http.StatusBadRequest, "INVALID_DECISION", "unsupported decision")
	}
}

// dispatchOneShotC2Command persists a command and pushes it on the live agent stream (subset of ExecuteAgentCommand).
func (h *Handlers) dispatchOneShotC2Command(ctx context.Context, c echo.Context, agentID uuid.UUID, commandTypeStr string, params map[string]string, meta map[string]any) (uuid.UUID, error) {
	proto := mapCommandType(normalizeCommandType(commandTypeStr))
	if proto == edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED {
		return uuid.Nil, fmt.Errorf("unknown command type %q", commandTypeStr)
	}
	commandID := uuid.New()
	if h.commandRepo != nil {
		pAny := make(map[string]any, len(params))
		for k, v := range params {
			pAny[k] = v
		}
		if user := getCurrentUser(c); user != nil {
			if meta == nil {
				meta = map[string]any{}
			}
			meta["issued_by_username"] = user.Username
			if len(user.Roles) > 0 {
				meta["issued_by_role"] = user.Roles[0]
			}
		}
		dbCmd := &models.Command{
			ID:             commandID,
			AgentID:        agentID,
			CommandType:    models.CommandType(commandTypeStr),
			Parameters:     pAny,
			Priority:       5,
			Status:         models.CommandStatusPending,
			TimeoutSeconds: 300,
			IssuedBy:       nil,
			Metadata:       meta,
		}
		if err := h.commandRepo.Create(ctx, dbCmd); err != nil {
			return uuid.Nil, fmt.Errorf("persist command: %w", err)
		}
	}
	cmd := &edrv1.Command{
		CommandId:  commandID.String(),
		Timestamp:  timestamppb.Now(),
		Type:       proto,
		Parameters: params,
		Priority:   5,
	}
	if err := h.registry.Send(agentID.String(), cmd); err != nil {
		if h.commandRepo != nil {
			_ = h.commandRepo.UpdateStatus(ctx, commandID, models.CommandStatusFailed, nil, err.Error())
		}
		return uuid.Nil, err
	}
	if h.commandRepo != nil {
		_ = h.commandRepo.UpdateStatus(ctx, commandID, models.CommandStatusSent, nil, "")
	}
	h.logger.WithFields(logrus.Fields{
		"agent_id": agentID, "command_id": commandID, "type": commandTypeStr,
	}).Info("[C2] Quarantine decision command dispatched")

	if h.auditRepo != nil && c != nil {
		ip, ua := auditContext(c)
		username := "unknown"
		userID := uuid.Nil
		if user := getCurrentUser(c); user != nil {
			username = user.Username
			if uid, parseErr := uuid.Parse(user.UserID); parseErr == nil {
				userID = uid
			}
		}
		entry := models.NewAuditLog(userID, username, models.AuditActionCommandExecuted, "agent", agentID).
			WithContext(ip, ua).
			WithDetails(fmt.Sprintf("quarantine_decision type=%s", commandTypeStr))
		go func() {
			actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.auditRepo.Create(actx, entry)
		}()
	}
	return commandID, nil
}
