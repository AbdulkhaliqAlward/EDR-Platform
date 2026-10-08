package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rulesync"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type runtimeRepo struct {
	database.RuleRepository
	row     *database.Rule
	err     error
	creates int
}

func (r *runtimeRepo) GetByID(context.Context, string) (*database.Rule, error) { return r.row, nil }
func (r *runtimeRepo) LoadAll(context.Context) ([]*database.Rule, error) {
	return []*database.Rule{r.row}, r.err
}
func (r *runtimeRepo) Create(_ context.Context, row *database.Rule) (*database.Rule, error) {
	r.creates++
	r.row = row
	return row, nil
}

const runtimeContent = `title: API fixture
id: 11111111-1111-4111-8111-111111111111
level: high
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\fixture.exe'
  condition: selection
`

func runtimeHandler(repo *runtimeRepo) *RuleHandler {
	h := NewRuleHandler(repo, nil)
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	h.runtime = rulesync.New(repo, engine, nil, nil)
	return h
}
func TestRuleAPIRejectsInvalidBeforeWriteAndReportsActivationFailure(t *testing.T) {
	repo := &runtimeRepo{}
	h := runtimeHandler(repo)
	body, _ := json.Marshal(CreateRuleRequest{ID: "11111111-1111-4111-8111-111111111111", Title: "Fixture", Content: "malformed"})
	out := httptest.NewRecorder()
	h.CreateRule(out, httptest.NewRequest("POST", "/sigma/rules", strings.NewReader(string(body))))
	require.Equal(t, http.StatusBadRequest, out.Code)
	require.Zero(t, repo.creates)
	repo.err = errors.New("synthetic activation outage")
	body, _ = json.Marshal(CreateRuleRequest{ID: "11111111-1111-4111-8111-111111111111", Title: "Fixture", Content: runtimeContent})
	out = httptest.NewRecorder()
	h.CreateRule(out, httptest.NewRequest("POST", "/sigma/rules", strings.NewReader(string(body))))
	require.Equal(t, http.StatusServiceUnavailable, out.Code)
	require.Equal(t, 1, repo.creates)
	require.Contains(t, out.Body.String(), "stored")
	require.Equal(t, "high", repo.row.Severity)
	require.Equal(t, "process_creation", repo.row.Category)
}
func TestRuleAPIActuallyEvaluatesEvent(t *testing.T) {
	repo := &runtimeRepo{row: &database.Rule{ID: "11111111-1111-4111-8111-111111111111", Content: runtimeContent}}
	h := runtimeHandler(repo)
	for _, tc := range []struct {
		image   string
		matched bool
	}{{`C:\fixture.exe`, true}, {`C:\other.exe`, false}} {
		body, _ := json.Marshal(map[string]interface{}{"event": map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"executable": tc.image}}})
		req := mux.SetURLVars(httptest.NewRequest("POST", "/sigma/rules/id/test", strings.NewReader(string(body))), map[string]string{"rule_id": repo.row.ID})
		out := httptest.NewRecorder()
		h.TestRule(out, req)
		require.Equal(t, 200, out.Code)
		var response TestRuleResponse
		require.NoError(t, json.Unmarshal(out.Body.Bytes(), &response))
		require.Equal(t, tc.matched, response.Matched)
		require.Equal(t, true, response.Details["evaluated"])
	}
}
