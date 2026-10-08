package alert

import (
	"github.com/edr-platform/sigma-engine/internal/domain"
	"testing"
)

func TestCorrelatedMatchesPreserveHighestRuleLevel(t *testing.T) {
	event, err := domain.NewLogEvent(map[string]interface{}{"event_type": "powershell", "data": map[string]interface{}{"action": "script_block", "script_block_text": "Invoke-Expression $x"}})
	if err != nil {
		t.Fatal(err)
	}
	matches := domain.NewEventMatchResult(event)
	for _, level := range []string{"medium", "high", "high"} {
		matches.AddMatch(&domain.SigmaRule{ID: level, Title: "Overlapping script detection", Level: level}, 0.99, nil, nil)
	}
	a := NewAlertGenerator().GenerateAggregatedAlert(matches)
	if a == nil || a.Severity != domain.SeverityHigh {
		t.Fatalf("overlap must not promote High to Critical: %+v", a)
	}
}
