package rules

import (
	"github.com/edr-platform/sigma-engine/internal/domain"
	"strings"
)

// Allows applies the disk loader's configured level/status policy to DB rules.
func (q *QualityFilter) Allows(rule *domain.SigmaRule) bool {
	if q == nil {
		return true
	}
	if strings.TrimSpace(q.MinLevel) != "" && levelRank(rule.Level) < levelRank(q.MinLevel) {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(rule.Status))
	if q.SkipExperimental && status == "experimental" {
		return false
	}
	if len(q.AllowedStatus) == 0 {
		return status != "deprecated"
	}
	for _, allowed := range q.AllowedStatus {
		if strings.EqualFold(strings.TrimSpace(allowed), status) {
			return true
		}
	}
	return false
}
