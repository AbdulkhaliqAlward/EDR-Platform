package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Rule authoring: the Sigma YAML is the single source of truth. Title,
// severity (level), status, tags/MITRE and logsource are derived from it by
// the runtime's Validate, never taken from separate request fields that could
// disagree with the content that is actually evaluated.

const maxRuleIDLen = 128

var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ruleFromContent builds a stored-rule row from Sigma YAML. The ID comes from
// the YAML `id:`; requestID is only a fallback (and must agree when both are
// given). Without either, a UUID is generated and written into the content so
// exports and later edits keep the same identity.
func ruleFromContent(content, requestID string) (*database.Rule, error) {
	content = strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	if content == "" {
		return nil, fmt.Errorf("rule content (Sigma YAML) is required")
	}
	var head struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal([]byte(content), &head); err != nil {
		return nil, fmt.Errorf("invalid YAML: %v", err)
	}
	yamlID, requestID := strings.TrimSpace(head.ID), strings.TrimSpace(requestID)
	id := yamlID
	switch {
	case yamlID != "" && requestID != "" && !strings.EqualFold(yamlID, requestID):
		return nil, fmt.Errorf("request id %q differs from the YAML id %q", requestID, yamlID)
	case yamlID == "" && requestID != "":
		id = requestID
		content = "id: " + id + "\n" + content
	case yamlID == "":
		id = uuid.NewString()
		content = "id: " + id + "\n" + content
	}
	if len(id) > maxRuleIDLen || !ruleIDPattern.MatchString(id) {
		return nil, fmt.Errorf("rule id %q is invalid (letters, digits, . _ : - ; max %d)", id, maxRuleIDLen)
	}
	return &database.Rule{ID: id, Content: content + "\n", Enabled: true, Source: "custom", Version: 1}, nil
}

// RuleValidationRequest is the body of POST /sigma/rules/validate.
type RuleValidationRequest struct {
	ID      string                 `json:"id,omitempty"`
	Content string                 `json:"content"`
	Event   map[string]interface{} `json:"event,omitempty"` // optional sample event to test
}

// RuleValidationResponse describes what saving the content would store and
// whether the running detector would load it.
type RuleValidationResponse struct {
	Valid           bool        `json:"valid"`
	Error           string      `json:"error,omitempty"`
	ID              string      `json:"id,omitempty"`
	Title           string      `json:"title,omitempty"`
	Description     string      `json:"description,omitempty"`
	Severity        string      `json:"severity,omitempty"`
	Status          string      `json:"status,omitempty"`
	Product         string      `json:"product,omitempty"`
	Category        string      `json:"category,omitempty"`
	Service         string      `json:"service,omitempty"`
	MitreTactics    []string    `json:"mitre_tactics,omitempty"`
	MitreTechniques []string    `json:"mitre_techniques,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
	Exists          bool        `json:"exists"`
	WillActivate    bool        `json:"will_activate"`
	InactiveReason  string      `json:"inactive_reason,omitempty"`
	Tested          bool        `json:"tested"`
	Matched         bool        `json:"matched"`
	Matches         interface{} `json:"matches,omitempty"`
}

// ValidateRuleContent handles POST /api/v1/sigma/rules/validate: parse,
// compile and (optionally) test Sigma YAML without storing anything.
func (h *RuleHandler) ValidateRuleContent(w http.ResponseWriter, r *http.Request) {
	var req RuleValidationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if h.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "Rule runtime unavailable")
		return
	}
	row, err := ruleFromContent(req.Content, req.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, RuleValidationResponse{Valid: false, Error: err.Error()})
		return
	}
	if err := h.runtime.Validate(row); err != nil {
		writeJSON(w, http.StatusOK, RuleValidationResponse{Valid: false, Error: err.Error(), ID: row.ID})
		return
	}
	resp := RuleValidationResponse{Valid: true, ID: row.ID, Title: row.Title, Description: row.Description, Severity: row.Severity,
		Status: row.Status, Product: row.Product, Category: row.Category, Service: row.Service,
		MitreTactics: row.MitreTactics, MitreTechniques: row.MitreTechniques, Tags: row.Tags}
	if existing, _ := h.repo.GetByID(r.Context(), row.ID); existing != nil {
		resp.Exists = true
	}
	resp.WillActivate, resp.InactiveReason = h.runtime.Eligibility(row)
	if len(req.Event) > 0 {
		matches, err := h.runtime.Test(row, req.Event)
		if err != nil {
			resp.Error = "sample event: " + err.Error()
		} else {
			resp.Tested, resp.Matched, resp.Matches = true, len(matches) > 0, matches
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type authKindKey struct{}

// ctxAuthKind marks requests authenticated as a dashboard user (JWT), as
// opposed to service-to-service API-key calls.
var ctxAuthKind = authKindKey{}

// ruleWriterRoles mirrors the platform permission matrix (rules:write).
var ruleWriterRoles = map[string]bool{"admin": true, "security": true}

// requireRuleWriter enforces rules:write for dashboard users on the server,
// not only by hiding buttons in the UI. Service API-key calls are trusted.
func requireRuleWriter(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if kind, _ := r.Context().Value(ctxAuthKind).(string); kind == "user" {
			roles, _ := r.Context().Value("user_roles").([]string)
			allowed := false
			for _, role := range roles {
				if ruleWriterRoles[strings.ToLower(strings.TrimSpace(role))] {
					allowed = true
					break
				}
			}
			if !allowed {
				writeError(w, http.StatusForbidden, "Insufficient permissions: rules:write requires the admin or security role")
				return
			}
		}
		next(w, r)
	}
}
