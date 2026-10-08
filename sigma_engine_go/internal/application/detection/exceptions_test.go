package detection

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

type memExceptionSource struct {
	list []DetectionException
	hits map[string]int64
}

func (m *memExceptionSource) LoadExceptions(context.Context) ([]DetectionException, error) {
	return m.list, nil
}
func (m *memExceptionSource) RecordExceptionHits(_ context.Context, h map[string]int64) error {
	if m.hits == nil {
		m.hits = map[string]int64{}
	}
	for k, v := range h {
		m.hits[k] += v
	}
	return nil
}

func backupEvent(agent string) map[string]interface{} {
	return map[string]interface{}{
		"agent_id":   agent,
		"event_type": "process",
		"data": map[string]interface{}{
			"executable":        `C:\Program Files\Backup\agent.exe`,
			"command_line":      `"C:\Program Files\Backup\agent.exe" --nightly`,
			"parent_executable": `C:\Windows\System32\services.exe`,
		},
	}
}

func TestExceptionSuppressesOnlyMatchingRuleAndHost(t *testing.T) {
	src := &memExceptionSource{list: []DetectionException{{
		ID: "ex1", RuleID: "RULE-A", AgentID: "agent-11111111-1111-1111-1111-111111111111",
		Conditions: []ExceptionCondition{
			{Field: "Image", Op: "equals", Value: `c:\program files\backup\agent.exe`},
			{Field: "ParentImage", Op: "endswith", Value: `\services.exe`},
		},
	}}}
	m := NewExceptionManager(src, time.Minute)
	require.NoError(t, m.Refresh(context.Background()))

	ruleA := &domain.SigmaRule{ID: "rule-a"}
	ruleB := &domain.SigmaRule{ID: "rule-b"}
	host := "11111111-1111-1111-1111-111111111111"

	ec := testContext(t, backupEvent(host))
	assert.True(t, m.suppresses(ruleA, ec.event, ec), "rule, host and all conditions match")
	assert.False(t, m.suppresses(ruleB, ec.event, ec), "other rules are unaffected")

	other := testContext(t, backupEvent("22222222-2222-2222-2222-222222222222"))
	assert.False(t, m.suppresses(ruleA, other.event, other), "other hosts are unaffected")

	raw := backupEvent(host)
	raw["data"].(map[string]interface{})["parent_executable"] = `C:\Users\x\evil.exe`
	partial := testContext(t, raw)
	assert.False(t, m.suppresses(ruleA, partial.event, partial), "ALL conditions must hold")

	m.flushHits(context.Background())
	assert.Equal(t, int64(1), src.hits["ex1"])
}

func TestExceptionSafety(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	src := &memExceptionSource{list: []DetectionException{
		{ID: "empty", Conditions: nil}, // no conditions: ignored, never hides everything
		{ID: "badop", Conditions: []ExceptionCondition{{Field: "Image", Op: "regex", Value: ".*"}}},
		{ID: "expired", Conditions: []ExceptionCondition{{Field: "Image", Op: "contains", Value: "backup"}}, ExpiresAt: &past},
	}}
	m := NewExceptionManager(src, time.Minute)
	require.NoError(t, m.Refresh(context.Background()))
	ec := testContext(t, backupEvent("h"))
	assert.False(t, m.suppresses(&domain.SigmaRule{ID: "x"}, ec.event, ec))

	var nilMgr *ExceptionManager
	assert.False(t, nilMgr.suppresses(&domain.SigmaRule{ID: "x"}, ec.event, ec), "no manager: nothing suppressed")
}

type uncertainExceptionSource struct {
	memExceptionSource
	tokens map[string]bool
	fail   bool
}

func (s *uncertainExceptionSource) RecordExceptionHitBatch(ctx context.Context, id string, hits map[string]int64) error {
	if s.tokens[id] {
		return nil
	}
	s.tokens[id] = true
	if err := s.RecordExceptionHits(ctx, hits); err != nil {
		return err
	}
	if s.fail {
		s.fail = false
		return errors.New("acknowledgement lost after commit")
	}
	return nil
}
func TestExceptionHitRetryDoesNotRepeatUncertainCommit(t *testing.T) {
	source := &uncertainExceptionSource{tokens: map[string]bool{}, fail: true}
	manager := NewExceptionManager(source, time.Minute)
	manager.hits["fixture"] = 1
	manager.flushHits(context.Background())
	manager.hits["fixture"] = 2
	manager.flushHits(context.Background())
	require.Equal(t, int64(3), source.hits["fixture"])
	require.Len(t, source.tokens, 2)
}

func TestExceptionManagerStopFlushesPendingHits(t *testing.T) {
	source := &memExceptionSource{}
	manager := NewExceptionManager(source, time.Hour)
	manager.Start(context.Background())
	manager.Start(context.Background())
	manager.hitsMu.Lock()
	manager.hits["fixture"] = 2
	manager.hitsMu.Unlock()
	manager.Stop()
	manager.Stop()
	require.Equal(t, int64(2), source.hits["fixture"])
}
