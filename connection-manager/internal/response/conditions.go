package response

import (
	"encoding/json"
	"strings"

	"github.com/edr-platform/connection-manager/internal/repository"
)

// Conditions is the structured automation-rule trigger (trigger_conditions):
//
//	{"severity": ["critical","high"], "rule_ids": ["<sigma rule uuid>"],
//	 "rule_patterns": ["ransom"], "mitre_techniques": ["T1486"],
//	 "min_risk_score": 70, "logic_operator": "AND"|"OR"}
//
// With AND (default) every set condition must hold; with OR at least one.
type Conditions struct {
	Severity        []string `json:"severity,omitempty"`
	RuleIDs         []string `json:"rule_ids,omitempty"`
	RulePatterns    []string `json:"rule_patterns,omitempty"`
	MitreTechniques []string `json:"mitre_techniques,omitempty"`
	MinRiskScore    float64  `json:"min_risk_score,omitempty"`
	LogicOperator   string   `json:"logic_operator,omitempty"`
}

// containmentSeverities are the alert severities for which automated
// containment (destructive actions) is permitted without an explicit,
// per-detection opt-in.
var containmentSeverities = map[string]bool{"high": true, "critical": true}

func cleanList(in []string, lower bool) []string {
	out := in[:0]
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if lower {
			s = strings.ToLower(s)
		} else {
			s = strings.ToUpper(s)
		}
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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
	c.Severity = cleanList(c.Severity, true)
	c.RuleIDs = cleanList(c.RuleIDs, true)
	c.RulePatterns = cleanList(c.RulePatterns, true)
	c.MitreTechniques = cleanList(c.MitreTechniques, false)
	if c.MinRiskScore < 0 {
		c.MinRiskScore = 0
	}
	if !strings.EqualFold(c.LogicOperator, "OR") {
		c.LogicOperator = "AND"
	} else {
		c.LogicOperator = "OR"
	}
	return c, len(c.Severity) > 0 || len(c.RuleIDs) > 0 || len(c.RulePatterns) > 0 ||
		len(c.MitreTechniques) > 0 || c.MinRiskScore > 0
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
	if len(c.RuleIDs) > 0 {
		results = append(results, c.listsAlertRule(a))
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
	if len(c.MitreTechniques) > 0 {
		hit := false
		for _, want := range c.MitreTechniques {
			for _, have := range a.MitreTechniques {
				h := strings.ToUpper(strings.TrimSpace(have))
				// T1059 also matches the sub-technique T1059.001.
				if h == want || strings.HasPrefix(h, want+".") {
					hit = true
					break
				}
			}
			if hit {
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
	if c.LogicOperator == "OR" {
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

func (c Conditions) listsRule(ruleID string) bool {
	id := strings.ToLower(strings.TrimSpace(ruleID))
	if id == "" {
		return false
	}
	for _, r := range c.RuleIDs {
		if r == id {
			return true
		}
	}
	return false
}

// ScopedForContainment reports whether the conditions are narrow enough to
// drive automated containment: they must be ANDed and either restrict the
// severity to high/critical only, or name the exact Sigma rules (an explicit,
// per-detection opt-in). Broad triggers (a risk score or a title substring
// alone) are not acceptable for destructive automation.
func (c Conditions) ScopedForContainment() bool {
	if c.LogicOperator == "OR" {
		return false
	}
	if len(c.RuleIDs) > 0 {
		return true
	}
	if len(c.Severity) == 0 {
		return false
	}
	for _, s := range c.Severity {
		if !containmentSeverities[s] {
			return false
		}
	}
	return true
}

// ContainmentAllowedFor is the runtime guardrail for an automated run of a
// playbook with destructive steps: the alert must be high/critical, or its
// rule must be listed explicitly in the automation rule.
func (c Conditions) ContainmentAllowedFor(a *repository.SigmaAlertRecord) bool {
	return containmentSeverities[strings.ToLower(a.Severity)] || c.listsAlertRule(a)
}

func (c Conditions) listsAlertRule(a *repository.SigmaAlertRecord) bool {
	if c.listsRule(a.RuleID) {
		return true
	}
	for _, id := range a.RelatedRuleIDs {
		if c.listsRule(id) {
			return true
		}
	}
	return false
}
