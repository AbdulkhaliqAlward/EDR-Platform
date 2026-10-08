package response

import (
	"encoding/json"
	"strings"

	"github.com/edr-platform/connection-manager/internal/repository"
)

// Conditions is the structured automation-rule trigger (trigger_conditions):
//
//	{"severity": ["critical","high"], "rule_patterns": ["ransom"],
//	 "min_risk_score": 70, "logic_operator": "AND"|"OR"}
//
// With AND (default) every set condition must hold; with OR at least one.
type Conditions struct {
	Severity      []string `json:"severity,omitempty"`
	RulePatterns  []string `json:"rule_patterns,omitempty"`
	MinRiskScore  float64  `json:"min_risk_score,omitempty"`
	LogicOperator string   `json:"logic_operator,omitempty"`
}

// ParseConditions decodes trigger_conditions. ok is false when the JSON is
// invalid or sets no supported condition (e.g. legacy free-text
// {"condition": "..."}); such a rule must never match — matching everything
// would be the unsafe failure mode.
func ParseConditions(raw json.RawMessage) (Conditions, bool) {
	var c Conditions
	if len(raw) == 0 || json.Unmarshal(raw, &c) != nil {
		return Conditions{}, false
	}
	sev := c.Severity[:0]
	for _, s := range c.Severity {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			sev = append(sev, s)
		}
	}
	c.Severity = sev
	pats := c.RulePatterns[:0]
	for _, p := range c.RulePatterns {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			pats = append(pats, p)
		}
	}
	c.RulePatterns = pats
	if c.MinRiskScore < 0 {
		c.MinRiskScore = 0
	}
	return c, len(c.Severity) > 0 || len(c.RulePatterns) > 0 || c.MinRiskScore > 0
}

// Matches evaluates the conditions against an alert.
func (c Conditions) Matches(a *repository.SigmaAlertRecord) bool {
	var results []bool
	if len(c.Severity) > 0 {
		sev := strings.ToLower(a.Severity)
		hit := false
		for _, s := range c.Severity {
			if s == sev {
				hit = true
				break
			}
		}
		results = append(results, hit)
	}
	if len(c.RulePatterns) > 0 {
		title, id := strings.ToLower(a.RuleTitle), strings.ToLower(a.RuleID)
		hit := false
		for _, p := range c.RulePatterns {
			if strings.Contains(title, p) || strings.Contains(id, p) {
				hit = true
				break
			}
		}
		results = append(results, hit)
	}
	if c.MinRiskScore > 0 {
		results = append(results, float64(a.RiskScore) >= c.MinRiskScore)
	}
	if len(results) == 0 {
		return false
	}
	if strings.EqualFold(c.LogicOperator, "OR") {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}
