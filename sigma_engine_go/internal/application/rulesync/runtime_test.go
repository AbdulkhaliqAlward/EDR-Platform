package rulesync

import (
	"context"
	"errors"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

type source struct {
	database.RuleRepository
	rows []*database.Rule
	err  error
}

func TestLegacySeededRuleLoadsAndDetects(t *testing.T) {
	for _, condition := range []string{"selection", "all of them", "1 of selection*"} {
		t.Run(condition, func(t *testing.T) { testLegacyRule(t, condition) })
	}
}

func testLegacyRule(t *testing.T, condition string) {
	r := row()
	r.Content = strings.Replace(r.Content, "condition: selection", "condition: "+condition, 1)
	original, err := rules.NewRuleParser(true).ParseContent(r.Content)
	require.NoError(t, err)
	legacy, err := yaml.Marshal(original) // exact historical seeding representation
	require.NoError(t, err)
	r.Content = string(legacy)
	parsed, err := Parse(r)
	require.NoError(t, err)
	require.Contains(t, parsed.Detection.Selections, "selection")
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	runtime := New(&source{rows: []*database.Rule{r}}, engine, nil, []string{"windows"})
	require.NoError(t, runtime.Refresh(context.Background()))
	for _, tc := range []struct {
		image   string
		matches int
	}{{`C:\fixture.exe`, 1}, {`C:\other.exe`, 0}} {
		event, err := domain.NewLogEvent(map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"action": "process_creation", "executable": tc.image}})
		require.NoError(t, err)
		require.Len(t, engine.Detect(event), tc.matches)
	}
	r.Enabled = false
	require.NoError(t, runtime.Refresh(context.Background()))
	require.Zero(t, engine.RuleCount(), "legacy compatibility must preserve disabled state")
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
