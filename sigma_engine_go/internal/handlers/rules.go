// Package handlers provides REST API handlers for Sigma Engine.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/gorilla/mux"
)

// RuleHandler handles rule management API endpoints.
type RuleHandler struct {
	repo        database.RuleRepository
	auditLogger *database.AuditLogger
	runtime     RuleRuntime
}

// RuleRuntime validates and activates edits in the running detector.
type RuleRuntime interface {
	Validate(*database.Rule) error
	Refresh(context.Context) error
	Test(*database.Rule, map[string]interface{}) ([]*domain.DetectionResult, error)
}

func (h *RuleHandler) validate(w http.ResponseWriter, row *database.Rule) bool {
	if h.runtime == nil {
		writeError(w, 503, "Rule runtime unavailable")
		return false
	}
	if err := h.runtime.Validate(row); err != nil {
		writeError(w, 400, err.Error())
		return false
	}
	return true
}
func (h *RuleHandler) activate(w http.ResponseWriter, r *http.Request) bool {
	if h.runtime == nil {
		writeError(w, 503, "Rule stored; runtime activation unavailable")
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := h.runtime.Refresh(ctx); err != nil {
		logger.Errorf("Rule runtime activation failed: %v", err)
		writeError(w, 503, "Rule stored; runtime activation pending retry")
		return false
	}
	return true
}

// NewRuleHandler creates a new rule handler.
func NewRuleHandler(repo database.RuleRepository, auditLogger *database.AuditLogger) *RuleHandler {
	return &RuleHandler{repo: repo, auditLogger: auditLogger}
}

// RegisterRoutes registers rule routes on the router.
func (h *RuleHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/sigma/rules", h.ListRules).Methods("GET")
	r.HandleFunc("/sigma/rules", h.CreateRule).Methods("POST")
	r.HandleFunc("/sigma/rules/{rule_id}", h.GetRule).Methods("GET")
	r.HandleFunc("/sigma/rules/{rule_id}", h.UpdateRule).Methods("PUT")
	r.HandleFunc("/sigma/rules/{rule_id}", h.DeleteRule).Methods("DELETE")
	r.HandleFunc("/sigma/rules/{rule_id}/enable", h.EnableRule).Methods("PATCH")
	r.HandleFunc("/sigma/rules/{rule_id}/disable", h.DisableRule).Methods("PATCH")
	r.HandleFunc("/sigma/rules/bulk-import", h.BulkImportRules).Methods("POST")
	r.HandleFunc("/sigma/rules/{rule_id}/test", h.TestRule).Methods("POST")
}

// RuleResponse is the API response for a rule.
type RuleResponse struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Description     string     `json:"description,omitempty"`
	Severity        string     `json:"severity"`
	Category        string     `json:"category,omitempty"`
	Product         string     `json:"product,omitempty"`
	Enabled         bool       `json:"enabled"`
	Status          string     `json:"status"`
	MitreTactics    []string   `json:"mitre_tactics,omitempty"`
	MitreTechniques []string   `json:"mitre_techniques,omitempty"`
	Author          string     `json:"author,omitempty"`
	Source          string     `json:"source"`
	DateCreated     *time.Time `json:"date_created,omitempty"`
	DateModified    *time.Time `json:"date_modified,omitempty"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

// RulesListResponse is the API response for listing rules.
type RulesListResponse struct {
	Count  int             `json:"count"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	Rules  []*RuleResponse `json:"rules"`
}

// CreateRuleRequest is the request body for creating a rule.
type CreateRuleRequest struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Content     string   `json:"content"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category,omitempty"`
	Product     string   `json:"product,omitempty"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// ListRules handles GET /api/v1/sigma/rules
func (h *RuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	filters := database.RuleFilters{
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
	if v := r.URL.Query().Get("enabled"); v != "" {
		enabled := v == "true"
		filters.Enabled = &enabled
	}
	if v := r.URL.Query().Get("product"); v != "" {
		filters.Product = v
	}
	if v := r.URL.Query().Get("category"); v != "" {
		filters.Category = v
	}
	if v := r.URL.Query().Get("severity"); v != "" {
		filters.Severity = v
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
	rules, total, err := h.repo.List(ctx, filters)
	if err != nil {
		logger.Errorf("Failed to list rules: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to list rules")
		return
	}

	// Convert to response
	response := RulesListResponse{
		Count:  len(rules),
		Total:  total,
		Limit:  filters.Limit,
		Offset: filters.Offset,
		Rules:  make([]*RuleResponse, 0, len(rules)),
	}

	for _, rule := range rules {
		response.Rules = append(response.Rules, toRuleResponse(rule))
	}

	writeJSON(w, http.StatusOK, response)
}

// CreateRule handles POST /api/v1/sigma/rules
func (h *RuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "Rule ID is required")
		return
	}
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "Rule title is required")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "Rule content is required")
		return
	}

	// Check if rule exists
	existing, _ := h.repo.GetByID(ctx, req.ID)
	if existing != nil {
		writeError(w, http.StatusConflict, "Rule with this ID already exists")
		return
	}

	// Create rule
	rule := &database.Rule{
		ID:          req.ID,
		Title:       req.Title,
		Description: req.Description,
		Content:     req.Content,
		Severity:    req.Severity,
		Category:    req.Category,
		Product:     req.Product,
		Status:      req.Status,
		Enabled:     true,
		Tags:        req.Tags,
		Source:      "custom",
		Version:     1,
	}

	if rule.Status == "" {
		rule.Status = "stable"
	}

	if !h.validate(w, rule) {
		return
	}
	created, err := h.repo.Create(ctx, rule)
	if err != nil {
		logger.Errorf("Failed to create rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to create rule")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "create_rule", "Rule", rule.ID, username, userID, ip, "success", "Created custom rule: "+rule.Title)
	}

	if !h.activate(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, toRuleResponse(created))
}

// GetRule handles GET /api/v1/sigma/rules/{rule_id}
func (h *RuleHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	rule, err := h.repo.GetByID(ctx, ruleID)
	if err != nil {
		logger.Errorf("Failed to get rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to get rule")
		return
	}
	if rule == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	writeJSON(w, http.StatusOK, toRuleResponse(rule))
}

// UpdateRule handles PUT /api/v1/sigma/rules/{rule_id}
func (h *RuleHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	// Check if rule exists
	existing, err := h.repo.GetByID(ctx, ruleID)
	if err != nil || existing == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Update rule
	existing.Title = req.Title
	existing.Description = req.Description
	existing.Content = req.Content
	existing.Severity = req.Severity
	existing.Category = req.Category
	existing.Product = req.Product
	existing.Status = req.Status
	existing.Tags = req.Tags

	if !h.validate(w, existing) {
		return
	}
	updated, err := h.repo.Update(ctx, ruleID, existing)
	if err != nil {
		logger.Errorf("Failed to update rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to update rule")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "update_rule", "Rule", ruleID, username, userID, ip, "success", "Updated rule: "+existing.Title)
	}

	if !h.activate(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, toRuleResponse(updated))
}

// DeleteRule handles DELETE /api/v1/sigma/rules/{rule_id}
func (h *RuleHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	// Check if rule exists
	existing, _ := h.repo.GetByID(ctx, ruleID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	if err := h.repo.Delete(ctx, ruleID); err != nil {
		logger.Errorf("Failed to delete rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete rule")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "delete_rule", "Rule", ruleID, username, userID, ip, "success", "Deleted rule")
	}

	if !h.activate(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnableRule handles PATCH /api/v1/sigma/rules/{rule_id}/enable
func (h *RuleHandler) EnableRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	// Check if rule exists
	existing, _ := h.repo.GetByID(ctx, ruleID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	if !h.validate(w, existing) {
		return
	}
	if err := h.repo.Enable(ctx, ruleID); err != nil {
		logger.Errorf("Failed to enable rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to enable rule")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "enable_rule", "Rule", ruleID, username, userID, ip, "success", "Enabled rule")
	}

	if !h.activate(w, r) {
		return
	}
	existing.Enabled = true
	writeJSON(w, http.StatusOK, toRuleResponse(existing))
}

// DisableRule handles PATCH /api/v1/sigma/rules/{rule_id}/disable
func (h *RuleHandler) DisableRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	// Check if rule exists
	existing, _ := h.repo.GetByID(ctx, ruleID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	if err := h.repo.Disable(ctx, ruleID); err != nil {
		logger.Errorf("Failed to disable rule: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to disable rule")
		return
	}

	if h.auditLogger != nil {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "disable_rule", "Rule", ruleID, username, userID, ip, "success", "Disabled rule")
	}

	if !h.activate(w, r) {
		return
	}
	existing.Enabled = false
	writeJSON(w, http.StatusOK, toRuleResponse(existing))
}

// BulkImportRequest is the request for bulk importing rules.
type BulkImportRequest struct {
	Rules []*CreateRuleRequest `json:"rules"`
}

// BulkImportResponse is the response for bulk import.
type BulkImportResponse struct {
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// BulkImportRules handles POST /api/v1/sigma/rules/bulk-import
func (h *RuleHandler) BulkImportRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req BulkImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Rules) == 0 {
		writeError(w, http.StatusBadRequest, "No rules provided")
		return
	}

	response := BulkImportResponse{
		Errors: make([]string, 0),
	}

	for _, ruleReq := range req.Rules {
		if ruleReq == nil {
			response.Failed++
			response.Errors = append(response.Errors, "Missing rule")
			continue
		}
		rule := &database.Rule{
			ID:          ruleReq.ID,
			Title:       ruleReq.Title,
			Description: ruleReq.Description,
			Content:     ruleReq.Content,
			Severity:    ruleReq.Severity,
			Category:    ruleReq.Category,
			Product:     ruleReq.Product,
			Status:      ruleReq.Status,
			Tags:        ruleReq.Tags,
			Enabled:     true,
			Source:      "imported",
			Version:     1,
		}

		if rule.Status == "" {
			rule.Status = "stable"
		}
		var validation error
		if h.runtime == nil {
			validation = fmt.Errorf("rule runtime unavailable")
		} else {
			validation = h.runtime.Validate(rule)
		}
		if validation != nil {
			response.Failed++
			response.Errors = append(response.Errors, rule.ID+": "+validation.Error())
			continue
		}
		if _, err := h.repo.Create(ctx, rule); err != nil {
			response.Failed++
			response.Errors = append(response.Errors, ruleReq.ID+": "+err.Error())
		} else {
			response.Imported++
		}
	}

	if h.auditLogger != nil && response.Imported > 0 {
		userID, username, ip := getAuditContext(r)
		_ = h.auditLogger.Log(ctx, "bulk_import_rules", "Rule", "", username, userID, ip, "success", strconv.Itoa(response.Imported)+" rules imported successfully")
	}

	if response.Imported > 0 && !h.activate(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// TestRuleRequest is the request for testing a rule.
type TestRuleRequest struct {
	Event map[string]interface{} `json:"event"`
}

// TestRuleResponse is the response for rule testing.
type TestRuleResponse struct {
	Matched bool                   `json:"matched"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// TestRule handles POST /api/v1/sigma/rules/{rule_id}/test
func (h *RuleHandler) TestRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	ruleID := vars["rule_id"]

	// Check if rule exists
	existing, _ := h.repo.GetByID(ctx, ruleID)
	if existing == nil {
		writeError(w, http.StatusNotFound, "Rule not found")
		return
	}

	var req TestRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if h.runtime == nil {
		writeError(w, 503, "Rule runtime unavailable")
		return
	}
	matches, err := h.runtime.Test(existing, req.Event)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TestRuleResponse{Matched: len(matches) > 0, Details: map[string]interface{}{"rule_id": ruleID, "evaluated": true, "matches": matches}})

}

// toRuleResponse converts a database rule to API response.
func toRuleResponse(rule *database.Rule) *RuleResponse {
	return &RuleResponse{
		ID:              rule.ID,
		Title:           rule.Title,
		Description:     rule.Description,
		Severity:        rule.Severity,
		Category:        rule.Category,
		Product:         rule.Product,
		Enabled:         rule.Enabled,
		Status:          rule.Status,
		MitreTactics:    rule.MitreTactics,
		MitreTechniques: rule.MitreTechniques,
		Author:          rule.Author,
		Source:          rule.Source,
		DateCreated:     rule.DateCreated,
		DateModified:    rule.DateModified,
		CreatedAt:       rule.CreatedAt,
		UpdatedAt:       rule.UpdatedAt,
	}
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
