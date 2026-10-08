// Package handlers provides Alert Management API endpoints.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/scoring"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/gorilla/mux"
)

// AlertHandler handles alert management API endpoints.
type AlertHandler struct {
	repo        database.AlertRepository
	auditLogger *database.AuditLogger
	riskLevels  scoring.RiskLevelsConfig
}

// NewAlertHandler creates a new alert handler.
func NewAlertHandler(repo database.AlertRepository, auditLogger *database.AuditLogger, riskLevels scoring.RiskLevelsConfig) *AlertHandler {
	return &AlertHandler{repo: repo, auditLogger: auditLogger, riskLevels: riskLevels}
}

// getAuditContext extracts common audit fields.
func getAuditContext(r *http.Request) (string, string, string) {
	ctx := r.Context()
	userID := ""
	username := "system"
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}

	if v, ok := ctx.Value("user_id").(string); ok {
		userID = v
	}
	if v, ok := ctx.Value("username").(string); ok {
		username = v
	}
	return userID, username, ip
}

// RegisterRoutes registers alert routes on the router.
func (h *AlertHandler) RegisterRoutes(r *mux.Router) {
	// Bulk operations MUST be registered before {alert_id} wildcard to avoid mux conflicts
	r.HandleFunc("/sigma/alerts/bulk/status", h.BulkUpdateAlertStatus).Methods("PATCH")
	r.HandleFunc("/sigma/alerts", h.QueryAlerts).Methods("GET")
	r.HandleFunc("/sigma/alerts/{alert_id}", h.GetAlert).Methods("GET")
	r.HandleFunc("/sigma/alerts/{alert_id}/status", h.UpdateAlertStatus).Methods("PATCH")
	r.HandleFunc("/sigma/alerts/{alert_id}/acknowledge", h.AcknowledgeAlert).Methods("POST")
	r.HandleFunc("/sigma/alerts/{alert_id}", h.DeleteAlert).Methods("DELETE")
}

// AlertResponse is the API response for an alert.
type AlertResponse struct {
	ID                string                 `json:"id"`
	Timestamp         time.Time              `json:"timestamp"`
	AgentID           string                 `json:"agent_id"`
	RuleID            string                 `json:"rule_id"`
	RuleTitle         string                 `json:"rule_title"`
	Severity          string                 `json:"severity"`
	Category          string                 `json:"category,omitempty"`
	EventCount        int                    `json:"event_count"`
	EventIDs          []string               `json:"event_ids,omitempty"`
	MitreTactics      []string               `json:"mitre_tactics,omitempty"`
	MitreTechniques   []string               `json:"mitre_techniques,omitempty"`
	MatchedFields     map[string]interface{} `json:"matched_fields,omitempty"`
	ContextData       map[string]interface{} `json:"context_data,omitempty"`
	Status            string                 `json:"status"`
	AssignedTo        string                 `json:"assigned_to,omitempty"`
	ResolutionNotes   string                 `json:"resolution_notes,omitempty"`
	Confidence        *float64               `json:"confidence,omitempty"`
	FalsePositiveRisk *float64               `json:"false_positive_risk,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`

	// ── Context-Aware Risk Scoring (Phase 1) ─────────────────────────────────
	// These fields are computed by RiskScorer and persisted as JSONB in the DB.
	// They were previously omitted from this struct, causing an empty Context tab.
	RiskScore       int                    `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level,omitempty"`
	ContextSnapshot map[string]interface{} `json:"context_snapshot,omitempty"`
	ScoreBreakdown  map[string]interface{} `json:"score_breakdown,omitempty"`

	// ── Alert Aggregation metadata ───────────────────────────────────────────
	MatchCount         *int     `json:"match_count,omitempty"`
	RelatedRuleIDs     []string `json:"related_rule_ids,omitempty"`
	RelatedRules       []string `json:"related_rules,omitempty"`
	CombinedConfidence *float64 `json:"combined_confidence,omitempty"`
	SeverityPromoted   *bool    `json:"severity_promoted,omitempty"`
	OriginalSeverity   string   `json:"original_severity,omitempty"`

	// ── Analyst-friendly enrichment (computed, not stored) ──────────────────
	HumanSummary   string `json:"human_summary,omitempty"`
	SourceHostname string `json:"source_hostname,omitempty"`
}

// AlertsListResponse is the API response for listing alerts.
type AlertsListResponse struct {
	Count  int              `json:"count"`
	Total  int64            `json:"total"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
	Alerts []*AlertResponse `json:"alerts"`
}

// QueryAlerts handles GET /api/v1/sigma/alerts
func (h *AlertHandler) QueryAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filters := database.AlertFilters{
		Limit:  100,
		Offset: 0,
	}

	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 && limit <= 1000 {
			filters.Limit = limit
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if offset, err := strconv.Atoi(v); err == nil && offset >= 0 {
			filters.Offset = offset
		}
	}
	if v := r.URL.Query().Get("agent_id"); v != "" {
		filters.AgentID = v
	}
	if v := r.URL.Query().Get("rule_id"); v != "" {
		filters.RuleID = v
	}
	if v := r.URL.Query().Get("severity"); v != "" {
		filters.Severity = strings.Split(v, ",")
	}
	if v := r.URL.Query().Get("status"); v != "" {
		filters.Status = strings.Split(v, ",")
	}
	if v := r.URL.Query().Get("date_from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filters.DateFrom = t
		}
	}
	if v := r.URL.Query().Get("date_to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filters.DateTo = t
		}
	}
	if v := r.URL.Query().Get("search"); v != "" {
		filters.Search = v
	}
	if v := r.URL.Query().Get("sort"); v != "" {
		if strings.HasPrefix(v, "-") {
			filters.SortBy = strings.TrimPrefix(v, "-")
			filters.SortOrder = "desc"
		} else {
			filters.SortBy = v
			filters.SortOrder = "asc"
		}
	}

	// Query database
	alerts, total, err := h.repo.List(ctx, filters)
	if err != nil {
		logger.Errorf("Failed to query alerts: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to query alerts")
		return
	}

	// Convert to response
	response := AlertsListResponse{
		Count:  len(alerts),
		Total:  total,
		Limit:  filters.Limit,
		Offset: filters.Offset,
		Alerts: make([]*AlertResponse, 0, len(alerts)),
	}

	for _, alert := range alerts {
		response.Alerts = append(response.Alerts, h.toAlertResponse(alert))
	}

	writeJSON(w, http.StatusOK, response)
}

// GetAlert handles GET /api/v1/sigma/alerts/{alert_id}
func (h *AlertHandler) GetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	alertID := vars["alert_id"]

	alert, err := h.repo.GetByID(ctx, alertID)
	if err != nil {
		logger.Errorf("Failed to get alert: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to get alert")
		return
	}
	if alert == nil {
		writeError(w, http.StatusNotFound, "Alert not found")
		return
	}

	writeJSON(w, http.StatusOK, h.toAlertResponse(alert))
}

// UpdateStatusRequest is the request for updating alert status.
type UpdateStatusRequest struct {
	Status string `json:"status"`
	Notes  string `json:"notes,omitempty"`
}

// UpdateAlertStatus handles PATCH /api/v1/sigma/alerts/{alert_id}/status
func (h *AlertHandler) UpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	alertID := vars["alert_id"]

	// Check if alert exists
	existing, _ := h.repo.GetByID(ctx, alertID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Alert not found")
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate status
	validStatuses := map[string]bool{
		"open":           true,
		"acknowledged":   true,
		"investigating":  true,
		"resolved":       true,
		"false_positive": true,
		"suppressed":     true,
	}
	if !validStatuses[req.Status] {
		writeError(w, http.StatusBadRequest, "Invalid status value")
		return
	}

	if err := h.repo.UpdateStatus(ctx, alertID, req.Status, req.Notes); err != nil {
		logger.Errorf("Failed to update alert status: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to update alert status")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "update_alert_status", "Alert", alertID, username, userID, ip, "success", "Updated alert status to "+req.Status)
	}

	existing.Status = req.Status
	existing.ResolutionNotes = req.Notes
	writeJSON(w, http.StatusOK, h.toAlertResponse(existing))
}

// AcknowledgeAlert handles POST /api/v1/sigma/alerts/{alert_id}/acknowledge
func (h *AlertHandler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	alertID := vars["alert_id"]

	// Check if alert exists
	existing, _ := h.repo.GetByID(ctx, alertID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Alert not found")
		return
	}

	if err := h.repo.UpdateStatus(ctx, alertID, "acknowledged", ""); err != nil {
		logger.Errorf("Failed to acknowledge alert: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to acknowledge alert")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "acknowledge_alert", "Alert", alertID, username, userID, ip, "success", "Acknowledged alert")
	}

	existing.Status = "acknowledged"
	writeJSON(w, http.StatusOK, h.toAlertResponse(existing))
}

// DeleteAlert handles DELETE /api/v1/sigma/alerts/{alert_id}
func (h *AlertHandler) DeleteAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	alertID := vars["alert_id"]

	// Check if alert exists
	existing, _ := h.repo.GetByID(ctx, alertID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Alert not found")
		return
	}

	if err := h.repo.Delete(ctx, alertID); err != nil {
		logger.Errorf("Failed to delete alert: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete alert")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "delete_alert", "Alert", alertID, username, userID, ip, "success", "Deleted alert")
	}

	w.WriteHeader(http.StatusNoContent)
}

// toAlertResponse converts a database alert to API response.
// IMPORTANT: All context-aware risk scoring fields MUST be mapped here.
// Previously risk_score, context_snapshot, score_breakdown were stored in the
// DB but silently dropped at this conversion step, causing the empty Context
// tab on the dashboard. All fields are now forwarded.
func toAlertResponse(alert *database.Alert) *AlertResponse {
	return toAlertResponseWithRiskLevels(alert, scoring.DefaultRiskScoringConfig().RiskLevels)
}

func toAlertResponseWithRiskLevels(alert *database.Alert, riskLevels scoring.RiskLevelsConfig) *AlertResponse {
	resp := &AlertResponse{
		ID:                alert.ID,
		Timestamp:         alert.Timestamp,
		AgentID:           alert.AgentID,
		RuleID:            alert.RuleID,
		RuleTitle:         alert.RuleTitle,
		Severity:          alert.Severity,
		Category:          alert.Category,
		EventCount:        alert.EventCount,
		EventIDs:          alert.EventIDs,
		MitreTactics:      alert.MitreTactics,
		MitreTechniques:   alert.MitreTechniques,
		MatchedFields:     alert.MatchedFields,
		ContextData:       alert.ContextData,
		Status:            alert.Status,
		AssignedTo:        alert.AssignedTo,
		ResolutionNotes:   alert.ResolutionNotes,
		Confidence:        alert.Confidence,
		FalsePositiveRisk: alert.FalsePositiveRisk,
		CreatedAt:         alert.CreatedAt,
		UpdatedAt:         alert.UpdatedAt,
		// Context-Aware Risk Scoring
		RiskScore:       alert.RiskScore,
		RiskLevel:       scoring.RiskLevelFromScore(alert.RiskScore, riskLevels),
		ContextSnapshot: alert.ContextSnapshot,
		ScoreBreakdown:  alert.ScoreBreakdown,
		// Aggregation metadata
		MatchCount:         alert.MatchCount,
		RelatedRules:       alert.RelatedRules,
		RelatedRuleIDs:     alert.RelatedRuleIDs,
		CombinedConfidence: alert.CombinedConfidence,
		SeverityPromoted:   alert.SeverityPromoted,
		OriginalSeverity:   alert.OriginalSeverity,
	}

	// Analyst-friendly enrichment
	resp.HumanSummary = generateHumanSummary(alert)
	resp.SourceHostname = extractSourceHostname(alert)

	return resp
}

// generateHumanSummary creates a plain-English description of what the alert means.
func generateHumanSummary(alert *database.Alert) string {
	processName := ""
	cmdLine := ""
	userName := ""
	targetFile := ""

	// Extract from context data
	if cd := alert.ContextData; cd != nil {
		if data, ok := cd["data"].(map[string]interface{}); ok {
			if v, ok := data["command_line"].(string); ok {
				cmdLine = v
			}
			if v, ok := data["user_name"].(string); ok {
				userName = v
			}
			// The agent's "name" means different things per event type: the
			// process image name on process events, the file name on file
			// events (where the acting process is in process_name).
			name, _ := data["name"].(string)
			if v, ok := data["process_name"].(string); ok && v != "" {
				processName = v
				targetFile = name
			} else if cd["event_type"] == "file" {
				targetFile = name
			} else {
				processName = name
			}
		}
		if v, ok := cd["user_name"].(string); ok && userName == "" {
			userName = v
		}
	}

	// Extract from matched fields
	if mf := alert.MatchedFields; mf != nil {
		if v, ok := mf["TargetFilename"].(string); ok {
			// Get just the filename from a full path
			parts := strings.Split(strings.ReplaceAll(v, "/", "\\"), "\\")
			if len(parts) > 0 {
				targetFile = parts[len(parts)-1]
			}
		}
	}

	// Build category-specific summary
	switch alert.Category {
	case "process_creation":
		action := describeProcessAction(cmdLine, processName)
		if userName != "" {
			return fmt.Sprintf("%s (user: %s)", action, userName)
		}
		return action

	case "file_event":
		if targetFile != "" && processName != "" {
			return fmt.Sprintf("%s created or modified suspicious file \"%s\"", processName, targetFile)
		}
		if targetFile != "" {
			return fmt.Sprintf("Suspicious file activity detected: \"%s\"", targetFile)
		}
		return "Suspicious file system activity detected"

	default:
		if processName != "" {
			return fmt.Sprintf("%s triggered detection rule: %s", processName, alert.RuleTitle)
		}
		return fmt.Sprintf("Detection rule triggered: %s", alert.RuleTitle)
	}
}

// describeProcessAction creates a human-readable description of a process action.
func describeProcessAction(cmdLine, processName string) string {
	cmdLower := strings.ToLower(cmdLine)

	// Specific known patterns
	if strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "downloadfile") {
		return fmt.Sprintf("%s attempted to download and execute a remote script", processName)
	}
	if strings.Contains(cmdLower, "-encodedcommand") || strings.Contains(cmdLower, "-enc ") {
		return fmt.Sprintf("%s executed a Base64-encoded command (possible obfuscation)", processName)
	}
	if strings.Contains(cmdLower, "sekurlsa") || strings.Contains(cmdLower, "mimikatz") {
		return fmt.Sprintf("%s attempted credential dumping (Mimikatz-like activity)", processName)
	}
	if strings.Contains(cmdLower, "procdump") && strings.Contains(cmdLower, "lsass") {
		return fmt.Sprintf("%s attempted to dump LSASS process memory for credential theft", processName)
	}
	if strings.Contains(cmdLower, "shutdown") || strings.Contains(cmdLower, "restart") {
		return fmt.Sprintf("%s initiated system shutdown/restart", processName)
	}
	if strings.Contains(cmdLower, "whoami") {
		return fmt.Sprintf("%s performed user/privilege discovery (whoami)", processName)
	}
	if strings.Contains(cmdLower, "net user") || strings.Contains(cmdLower, "net localgroup") {
		return fmt.Sprintf("%s performed user/group enumeration", processName)
	}
	if strings.Contains(cmdLower, "ipconfig") || strings.Contains(cmdLower, "ifconfig") {
		return fmt.Sprintf("%s performed network configuration discovery", processName)
	}
	if strings.Contains(cmdLower, "certutil") {
		return fmt.Sprintf("%s used certutil (LOLBin — possible download or decode)", processName)
	}
	if strings.Contains(cmdLower, "rundll32") {
		return fmt.Sprintf("%s used rundll32 to execute code (possible defense evasion)", processName)
	}
	if strings.Contains(cmdLower, "-nop") && strings.Contains(cmdLower, "-w hidden") {
		return fmt.Sprintf("%s launched hidden PowerShell session (stealth execution)", processName)
	}

	// Generic fallback
	if processName != "" {
		return fmt.Sprintf("%s executed a suspicious command", processName)
	}
	return "Suspicious process execution detected"
}

// extractSourceHostname resolves the hostname from context_data.source.hostname.
func extractSourceHostname(alert *database.Alert) string {
	if cd := alert.ContextData; cd != nil {
		if src, ok := cd["source"].(map[string]interface{}); ok {
			if h, ok := src["hostname"].(string); ok && h != "" {
				return h
			}
		}
	}
	return ""
}

func (h *AlertHandler) toAlertResponse(alert *database.Alert) *AlertResponse {
	return toAlertResponseWithRiskLevels(alert, h.riskLevels)
}

// BulkUpdateRequest is the request for bulk updating alert status.
type BulkUpdateRequest struct {
	IDs      []string `json:"ids"`
	AlertIDs []string `json:"alert_ids"` // alias used by some frontend payloads
	Status   string   `json:"status"`
}

// BulkUpdateAlertStatus handles PATCH /api/v1/sigma/alerts/bulk/status
func (h *AlertHandler) BulkUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.repo == nil {
		writeError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}

	var req BulkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Accept either "ids" or "alert_ids"
	ids := req.IDs
	if len(ids) == 0 {
		ids = req.AlertIDs
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "ids or alert_ids is required")
		return
	}

	// Validate status
	validStatuses := map[string]bool{
		"open": true, "acknowledged": true, "investigating": true,
		"resolved": true, "false_positive": true, "suppressed": true,
	}
	if !validStatuses[req.Status] {
		writeError(w, http.StatusBadRequest, "Invalid status value")
		return
	}

	if err := h.repo.BulkUpdateStatus(ctx, ids, req.Status); err != nil {
		logger.Errorf("Failed to bulk update alert status: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to bulk update alert status")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		for _, v := range ids {
			_ = h.auditLogger.Log(ctx, "bulk_update_alert_status", "Alert", v, username, userID, ip, "success", "Bulk updated alert status to "+req.Status)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"updated": len(ids),
		"status":  req.Status,
	})
}
