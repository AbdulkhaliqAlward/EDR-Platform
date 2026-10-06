package command

import (
	"strings"
	"testing"
)

func TestRunCmdTier(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"no markers → diagnostic", map[string]string{}, tierDiagnostic},
		{"custom", map[string]string{"authz_tier": "custom"}, tierCustom},
		{"custom case-insensitive", map[string]string{"authz_tier": " CUSTOM "}, tierCustom},
		{"library", map[string]string{"authz_tier": "library"}, tierLibrary},
		{"explicit diagnostic", map[string]string{"authz_tier": "diagnostic"}, tierDiagnostic},
		{"legacy from_playbook → library", map[string]string{"from_playbook": "true"}, tierLibrary},
		{"authz_tier wins over legacy marker", map[string]string{"authz_tier": "diagnostic", "from_playbook": "true"}, tierDiagnostic},
		{"unknown tier → diagnostic", map[string]string{"authz_tier": "root"}, tierDiagnostic},
		{"from_playbook=false → diagnostic", map[string]string{"from_playbook": "false"}, tierDiagnostic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runCmdTier(tc.params); got != tc.want {
				t.Fatalf("runCmdTier(%v) = %q, want %q", tc.params, got, tc.want)
			}
		})
	}
}

func TestCapRunCmdOutput(t *testing.T) {
	small := []byte("hello")
	if got := capRunCmdOutput(small); got != "hello" {
		t.Fatalf("small output changed: %q", got)
	}
	big := []byte(strings.Repeat("a", maxRunCmdOutput+10))
	got := capRunCmdOutput(big)
	if !strings.HasPrefix(got, strings.Repeat("a", maxRunCmdOutput)) {
		t.Fatal("truncated output must keep the first maxRunCmdOutput bytes")
	}
	if !strings.Contains(got, "output truncated") {
		t.Fatal("truncated output must say it was truncated")
	}
}
