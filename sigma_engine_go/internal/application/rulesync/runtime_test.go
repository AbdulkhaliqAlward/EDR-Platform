package rulesync

import (
	"context"
	"errors"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/stretchr/testify/require"
	"testing"
)

type source struct {
	database.RuleRepository
	rows []*database.Rule
	err  error
}

func (s *source) LoadAll(context.Context) ([]*database.Rule, error) { return s.rows, s.err }
func row() *database.Rule {
	return &database.Rule{ID: "11111111-1111-4111-8111-111111111111", Enabled: true, Content: `title: Runtime fixture
id: 11111111-1111-4111-8111-111111111111
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\fixture.exe'
  condition: selection
`}
}
func TestRuntimeRefreshAndTestAreIndependent(t *testing.T) {
	db := &source{rows: []*database.Rule{row()}}
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	runtime := New(db, engine, nil, []string{"windows"})
	ctx := context.Background()
	event := map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"action": "process_creation", "executable": `C:\fixture.exe`}}
	logEvent, err := domain.NewLogEvent(event)
	require.NoError(t, err)
	require.NoError(t, runtime.Refresh(ctx))
	require.Len(t, engine.Detect(logEvent), 1)
	db.rows[0].Enabled = false
	require.NoError(t, runtime.Refresh(ctx))
	require.Empty(t, engine.Detect(logEvent))
	matched, err := runtime.Test(db.rows[0], event)
	require.NoError(t, err)
	require.Len(t, matched, 1)
	require.Equal(t, 0, engine.RuleCount(), "testing must not publish disabled rules")
	negative, err := runtime.Test(db.rows[0], map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"executable": `C:\other.exe`}})
	require.NoError(t, err)
	require.Empty(t, negative)
	db.rows[0].Enabled = true
	require.NoError(t, runtime.Refresh(ctx))
	db.err = errors.New("synthetic DB outage")
	require.Error(t, runtime.Refresh(ctx))
	require.Equal(t, 1, engine.RuleCount())
	db.err = nil
	db.rows = nil
	require.NoError(t, runtime.Refresh(ctx))
	require.Equal(t, 0, engine.RuleCount())
}
func TestParseRejectsMalformedMismatchedAndMultipleDocuments(t *testing.T) {
	r := row()
	r.ID = "other"
	_, err := Parse(r)
	require.Error(t, err)
	r = row()
	r.Content += "\n---\nunknown: value\n"
	_, err = Parse(r)
	require.Error(t, err)
	r = row()
	r.Content = "not a Sigma rule"
	_, err = Parse(r)
	require.Error(t, err)
}
