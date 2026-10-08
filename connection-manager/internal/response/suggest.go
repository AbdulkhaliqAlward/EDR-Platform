package response

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// Suggestion is a ranked playbook recommendation for an alert.
type Suggestion struct {
	PlaybookID   string   `json:"playbook_id"`
	PlaybookName string   `json:"playbook_name"`
	Category     string   `json:"category"`
	Score        int      `json:"score"`
	Reasons      []string `json:"reasons"`
	// RuleID is set when an enabled automation rule matches the alert.
	RuleID string `json:"rule_id,omitempty"`
}

// rulePatternMatches evaluates a playbook's rule_pattern ("malware|trojan"),
// a case-insensitive RE2 regex; if it does not compile, its "|"-separated
// parts are matched as substrings.
func rulePatternMatches(pattern, text string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || text == "" {
		return false
	}
	if re, err := regexp.Compile("(?i)" + pattern); err == nil {
		return re.MatchString(text)
	}
	lt := strings.ToLower(text)
	for _, p := range strings.Split(strings.ToLower(pattern), "|") {
		if p = strings.TrimSpace(p); p != "" && strings.Contains(lt, p) {
			return true
		}
	}
	return false
}

// techniqueMatches reports whether two MITRE technique IDs refer to the same
// technique (T1055 matches T1055.012).
func techniqueMatches(a, b string) bool {
	a, b = strings.ToUpper(strings.TrimSpace(a)), strings.ToUpper(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

// Suggest ranks enabled playbooks for an alert using the playbooks' own
// matching metadata (severity filter, rule pattern, MITRE techniques) and
// enabled automation rules. A playbook whose severity filter excludes the
// alert's severity is never suggested. Results are sorted by score.
func Suggest(a *repository.SigmaAlertRecord, playbooks []*models.ResponsePlaybook, rules []*models.AutomationRule, limit int) []Suggestion {
	byID := make(map[string]*Suggestion)
	sev := strings.ToLower(a.Severity)
	text := a.RuleTitle + " " + a.RuleID

	for _, p := range playbooks {
		if p == nil || !p.Enabled {
			continue
		}
		s := &Suggestion{PlaybookID: p.ID.String(), PlaybookName: p.Name, Category: p.Category}
		if len(p.SeverityFilter) > 0 {
			hit := false
			for _, f := range p.SeverityFilter {
				if strings.EqualFold(f, sev) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			s.Score += 2
			s.Reasons = append(s.Reasons, "severity "+sev+" is in the playbook's severity filter")
		}
		if rulePatternMatches(p.RulePattern, text) {
			s.Score += 3
			s.Reasons = append(s.Reasons, "detection rule matches the playbook's rule pattern")
		}
		var techs []string
		for _, pt := range p.MITRETechiques {
			for _, at := range a.MitreTechniques {
				if techniqueMatches(pt, at) {
					techs = append(techs, strings.ToUpper(at))
					break
				}
			}
		}
		if len(techs) > 0 {
			bonus := 2 * len(techs)
			if bonus > 6 {
				bonus = 6
			}
			s.Score += bonus
			s.Reasons = append(s.Reasons, "shares MITRE techniques "+strings.Join(techs, ", "))
		}
		if (sev == "critical" || sev == "high") && strings.EqualFold(p.Category, "containment") {
			s.Score++
			s.Reasons = append(s.Reasons, "containment playbook for a "+sev+" alert")
		}
		byID[s.PlaybookID] = s
	}

	for _, r := range rules {
		if r == nil || !r.Enabled {
			continue
		}
		cond, ok := ParseConditions(r.TriggerConditions)
		if !ok || !cond.Matches(a) {
			continue
		}
		s, exists := byID[r.PlaybookID.String()]
		if !exists {
			continue // playbook disabled, deleted or excluded by its severity filter
		}
		s.Score += 5
		s.RuleID = r.ID.String()
		s.Reasons = append(s.Reasons, fmt.Sprintf("automation rule %q matches this alert", r.Name))
	}

	out := make([]Suggestion, 0, len(byID))
	for _, s := range byID {
		if s.Score > 0 {
			out = append(out, *s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].PlaybookName < out[j].PlaybookName
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
