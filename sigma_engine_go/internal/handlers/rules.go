// Package handlers provides REST API handlers for Sigma Engine.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/shared/pagination"
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
	// Eligibility reports whether Refresh would load the rule (quality filter
	// and product whitelist), with the reason when it would not.
	Eligibility(*database.Rule) (bool, string)
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
	r.HandleFunc("/sigma/rules", requireRuleWriter(h.CreateRule)).Methods("POST")
	r.HandleFunc("/sigma/rules/validate", requireRuleWriter(h.ValidateRuleContent)).Methods("POST")
	r.HandleFunc("/sigma/rules/{rule_id}", h.GetRule).Methods("GET")
	r.HandleFunc("/sigma/rules/{rule_id}", requireRuleWriter(h.UpdateRule)).Methods("PUT")
	r.HandleFunc("/sigma/rules/{rule_id}", requireRuleWriter(h.DeleteRule)).Methods("DELETE")
	r.HandleFunc("/sigma/rules/{rule_id}/enable", requireRuleWriter(h.EnableRule)).Methods("PATCH")
	r.HandleFunc("/sigma/rules/{rule_id}/disable", requireRuleWriter(h.DisableRule)).Methods("PATCH")
	r.HandleFunc("/sigma/rules/bulk-import", requireRuleWriter(h.BulkImportRules)).Methods("POST")
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
	Content         string     `json:"content,omitempty"` // Sigma YAML (detail view only)
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

	p, err := pagination.Parse(r.URL.Query(), pagination.Options{Scope: "sigma/rules", Offset: true, DefaultSort: "title", Sorts: database.RuleSortColumns})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filters := database.RuleFilters{Limit: p.Limit, Offset: p.Offset, SortBy: p.Sort, SortOrder: p.Order, Page: &p}
	if v := r.URL.Query().Get("enabled"); v != "" {
		if v != "true" && v != "false" {
			writeError(w, http.StatusBadRequest, "enabled must be true or false")
			return
		}
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
	if len(filters.Search) > 512 {
		writeError(w, http.StatusBadRequest, "search exceeds 512 characters")
		return
	}
	// Query database
	rules, total, err := h.repo.List(ctx, filters)
	if err != nil {
		logger.Errorf("Failed to list rules: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to list rules")
		return
	}

	records := make([]*RuleResponse, 0, len(rules))
	for _, rule := range rules {
		records = append(records, toRuleResponse(rule))
	}
	page := pagination.BuildOffset(records, p)
	if p.IncludeTotal {
		page.Total = &pagination.Total{Value: int(total)}
	}
	writeJSON(w, http.StatusOK, page)
}

// CreateRule handles POST /api/v1/sigma/rules
func (h *RuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// The Sigma YAML is authoritative: metadata is derived from it by
	// Validate; separate request fields are ignored so they can never
	// disagree with what the detector evaluates.
	rule, err := ruleFromContent(req.Content, req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if existing, _ := h.repo.GetByID(ctx, rule.ID); existing != nil {
		writeError(w, http.StatusConflict, "Rule with this ID already exists")
		return
	}
	if !h.validate(w, rule) {
		return
	}
	// A rule the running detector would never load must not be stored as
	// "active" silently.
	if ok, reason := h.runtime.Eligibility(rule); !ok {
		writeError(w, http.StatusUnprocessableEntity, "Rule is valid but would not be activated: "+reason)
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

	resp := toRuleResponse(rule)
	resp.Content = rule.Content
	writeJSON(w, http.StatusOK, resp)
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

	// The Sigma YAML is authoritative (see CreateRule); the ID is immutable.
	content := req.Content
	if strings.TrimSpace(content) == "" {
		content = existing.Content
	}
	parsed, err := ruleFromContent(content, ruleID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	existing.Content = parsed.Content
	existing.Title, existing.Description, existing.Severity, existing.Status = "", "", "", ""
	existing.Category, existing.Product, existing.Service, existing.Tags = "", "", "", nil
	if !h.validate(w, existing) {
		return
	}
	if ok, reason := h.runtime.Eligibility(existing); existing.Enabled && !ok {
		writeError(w, http.StatusUnprocessableEntity, "Rule is valid but would not be activated: "+reason+" (disable it first to keep it stored)")
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
