package service

import (
	"encoding/json"
	"testing"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// TestEvaluateAdvancedConditions checks the trigger_conditions shape emitted by
// the dashboard rule builder: {severity:[...], rule_patterns:[...], min_risk_score:N}.
func TestEvaluateAdvancedConditions(t *testing.T) {
	alert := &models.Alert{
		Severity:  models.AlertSeverityHigh,
		RuleName:  "Suspicious Ransomware File Encryption",
		RiskScore: 85,
	}

	cases := []struct {
		name string
		json string
		want bool
	}{
		{"severity match", `{"severity":["critical","high"]}`, true},
		{"severity mismatch", `{"severity":["low"]}`, false},
		{"pattern match case-insensitive", `{"rule_patterns":["RANSOMWARE"]}`, true},
		{"pattern mismatch", `{"rule_patterns":["lsass"]}`, false},
		{"one of several patterns", `{"rule_patterns":["lsass","encryption"]}`, true},
		{"non-string pattern ignored", `{"rule_patterns":[5,"ransom"]}`, true},
		{"risk at threshold", `{"min_risk_score":85}`, true},
		{"risk below threshold", `{"min_risk_score":90}`, false},
		{"zero risk threshold ignored", `{"min_risk_score":0}`, true},
		{"all conditions AND match", `{"severity":["high"],"rule_patterns":["ransom"],"min_risk_score":80}`, true},
		{"all conditions AND one fails", `{"severity":["high"],"rule_patterns":["ransom"],"min_risk_score":95}`, false},
	}

	s := &AutomationService{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cond map[string]interface{}
			if err := json.Unmarshal([]byte(tc.json), &cond); err != nil {
				t.Fatalf("bad test json: %v", err)
			}
			if got := s.evaluateAdvancedConditions(cond, alert); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
