package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
)

// TestBundledWindowsRulesParseAndCompile is a regression guard: every bundled
// SigmaHQ Windows rule must parse, and every rule that passes the production
// quality filters (config.yaml: level >= medium, status stable/test) must
// compile. A parser/matcher change that silently drops rules fails here.
func TestBundledWindowsRulesParseAndCompile(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sigma_rules", "rules", "windows")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("bundled rules not present: %v", err)
	}
	if testing.Short() {
		t.Skip("corpus test skipped in -short mode")
	}

	parser := rules.NewRuleParser(false)
	var parsed, eligible int
	var failures []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yml") {
			return err
		}
		r, perr := parser.ParseFile(path)
		if perr != nil {
			failures = append(failures, "parse "+path+": "+perr.Error())
			return nil
		}
		parsed++
		level, status := strings.ToLower(r.Level), strings.ToLower(r.Status)
		if (level != "medium" && level != "high" && level != "critical") || (status != "stable" && status != "test") {
			return nil
		}
		eligible++
		if _, cerr := compileRule(r); cerr != nil {
			failures = append(failures, "compile "+path+": "+cerr.Error())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("parsed=%d eligible=%d failures=%d", parsed, eligible, len(failures))
	if parsed == 0 {
		t.Fatal("no rules parsed")
	}
	for i, f := range failures {
		if i >= 20 {
			t.Errorf("... and %d more", len(failures)-20)
			break
		}
		t.Error(f)
	}
}
