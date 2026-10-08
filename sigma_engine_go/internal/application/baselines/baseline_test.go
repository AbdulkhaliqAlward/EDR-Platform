// Package baselines_test provides unit tests for the UEBA behavioral baseline
// subsystem (Sprint 4).
//
// Tests cover ShouldRecord, event-time extraction, hourly counting with
// batched flushes, and the per-hour rate statistics of the baseline.
package baselines_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ShouldRecord tests
// =============================================================================

// agentProcessEvent mirrors the Windows agent's wire format: a record UUID in
// the top-level event_id and the collector action under data.
func agentProcessEvent(action string) map[string]interface{} {
	return map[string]interface{}{
		"event_id":   "6f1c2d3e-0000-4000-8000-000000000001",
		"event_type": "process",
		"data":       map[string]interface{}{"name": "powershell.exe", "action": action},
	}
}

func TestShouldRecord_AgentProcessCreation(t *testing.T) {
	// Regression: the UUID event_id used to make this return false, so UEBA
	// never trained on agent telemetry.
	assert.True(t, baselines.ShouldRecord(agentProcessEvent("process_creation")))
}

func TestShouldRecord_AgentLegacyNoAction(t *testing.T) {
	assert.True(t, baselines.ShouldRecord(agentProcessEvent("")))
}

func TestShouldRecord_AgentTerminationAndSnapshot_False(t *testing.T) {
	assert.False(t, baselines.ShouldRecord(agentProcessEvent("process_termination")))
	assert.False(t, baselines.ShouldRecord(agentProcessEvent("snapshot")))
}

func TestShouldRecord_AgentNonProcess_False(t *testing.T) {
	assert.False(t, baselines.ShouldRecord(map[string]interface{}{
		"event_id":   "6f1c2d3e-0000-4000-8000-000000000002",
		"event_type": "dns",
		"data":       map[string]interface{}{"name": "example.com"},
	}))
}

func TestShouldRecord_EventLogCodes(t *testing.T) {
	assert.True(t, baselines.ShouldRecord(map[string]interface{}{"EventID": 1}))
	assert.True(t, baselines.ShouldRecord(map[string]interface{}{"EventID": float64(4688)}))
	assert.True(t, baselines.ShouldRecord(map[string]interface{}{"EventID": "4688"}))
	assert.True(t, baselines.ShouldRecord(map[string]interface{}{"data": map[string]interface{}{"event_id": "1"}}))
}

func TestShouldRecord_NameOnly_False(t *testing.T) {
	// A bare "name" is not evidence of a process start (DNS/pipe events have it too).
	assert.False(t, baselines.ShouldRecord(map[string]interface{}{"name": "svchost.exe"}))
}

func TestShouldRecord_NetworkEvent_False(t *testing.T) {
	// EventID 3 = Sysmon NetworkConnect — should NOT be recorded
	assert.False(t, baselines.ShouldRecord(map[string]interface{}{"EventID": 3}))
}

func TestShouldRecord_NilData_False(t *testing.T) {
	assert.False(t, baselines.ShouldRecord(nil))
}

// =============================================================================
// ExtractAggregationInput / EventTime
// =============================================================================

func TestExtractAggregationInput_UsesEventTime(t *testing.T) {
	ev := map[string]interface{}{
		"timestamp": "2026-10-01T03:15:00Z",
		"data":      map[string]interface{}{"name": "", "executable": `C:\Windows\System32\cmd.exe`},
	}
	in := baselines.ExtractAggregationInput("a1", ev)
	assert.Equal(t, "cmd.exe", in.ProcessName, "name falls back to the image basename")
	assert.Equal(t, time.Date(2026, 10, 1, 3, 15, 0, 0, time.UTC), in.ObservedAt)
}

func TestEventTime_InvalidIsZero(t *testing.T) {
	assert.True(t, baselines.EventTime(map[string]interface{}{"timestamp": "yesterday"}).IsZero())
}

// =============================================================================
// Aggregator + repository
// =============================================================================

func TestAggregator_CountsPerEventHourAndFlushes(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	agg := baselines.NewBaselineAggregator(repo, 0, 0)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		agg.Record(baselines.AggregationInput{AgentID: "a1", ProcessName: "CMD.exe", ObservedAt: now})
	}
	agg.Record(baselines.AggregationInput{AgentID: "a1", ProcessName: "cmd.exe", ObservedAt: now.Add(-3 * time.Hour)})
	// Too old for the baseline window: ignored.
	agg.Record(baselines.AggregationInput{AgentID: "a1", ProcessName: "cmd.exe", ObservedAt: now.Add(-30 * 24 * time.Hour)})

	assert.Equal(t, 3, agg.CurrentCount("a1", "cmd.exe", now), "current-hour count is available before the flush")
	agg.Flush(context.Background())

	b := repo.Buckets()
	require.Len(t, b, 2)
	assert.Equal(t, 1, b[0].Count)
	assert.Equal(t, 3, b[1].Count)
	assert.Equal(t, "cmd.exe", b[1].ProcessName, "process names are case-normalised")
}

func TestAggregatorRestoresObservedRatesWithoutRewritingThem(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	now := time.Now().UTC()
	old := baselines.NewBaselineAggregator(repo, 0, 0)
	for i := 0; i < 5; i++ {
		old.Record(baselines.AggregationInput{AgentID: "a1", ProcessName: "cmd.exe", ObservedAt: now})
	}
	old.Flush(context.Background())
	restarted := baselines.NewBaselineAggregator(repo, 0, 0)
	restarted.Start(context.Background())
	defer restarted.Stop()
	assert.Equal(t, 5, restarted.CurrentCount("a1", "CMD.exe", now))
	restarted.Flush(context.Background())
	require.Len(t, repo.Buckets(), 1)
	assert.Equal(t, 5, repo.Buckets()[0].Count, "restored counts must not be re-persisted")
	restarted.Record(baselines.AggregationInput{AgentID: "a1", ProcessName: "cmd.exe", ObservedAt: now})
	restarted.Flush(context.Background())
	assert.Equal(t, 6, restarted.CurrentCount("a1", "cmd.exe", now))
	assert.Equal(t, 6, repo.Buckets()[0].Count)
}

// seed writes `count` starts of proc in the given hour of `daysAgo` days ago,
// plus host activity (another process) so the slot counts as active.
func seed(repo *baselines.InMemoryBaselineRepository, ref time.Time, daysAgo, count int, proc string) {
	h := ref.Truncate(time.Hour).Add(-time.Duration(daysAgo) * 24 * time.Hour)
	counts := []baselines.HourlyCount{{AgentID: "a1", ProcessName: "explorer.exe", Hour: h, Count: 1}}
	if count > 0 {
		counts = append(counts, baselines.HourlyCount{AgentID: "a1", ProcessName: proc, Hour: h, Count: count})
	}
	_ = repo.AddCounts(context.Background(), counts)
}

func TestBaseline_RateStatisticsIncludeZeroSlots(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	ref := time.Date(2026, 10, 15, 10, 30, 0, 0, time.UTC)
	// 10 active days at 10:00; the process ran on 5 of them, 4 times each.
	for d := 1; d <= 10; d++ {
		n := 0
		if d%2 == 0 {
			n = 4
		}
		seed(repo, ref, d, n, "backup.exe")
	}
	b, err := repo.GetBaseline(context.Background(), "a1", "backup.exe", 10, ref.Truncate(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 10, b.HostActiveSlots)
	assert.Equal(t, 5, b.PresentSlots)
	assert.InDelta(t, 2.0, b.AvgExecutionsPerHour, 1e-9, "mean over active slots, zeros included")
	assert.InDelta(t, 2.0, b.StddevExecutions, 1e-9)
	assert.Equal(t, 10, b.HostObservedDays)
	require.NotNil(t, b.FirstSeenAt)
}

func TestBaseline_CurrentHourExcluded(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	ref := time.Date(2026, 10, 15, 10, 30, 0, 0, time.UTC)
	seed(repo, ref, 0, 50, "new.exe") // today's hour: must not enter the history
	fresh, err := repo.GetBaseline(context.Background(), "a1", "new.exe", 10, ref.Truncate(time.Hour))
	require.NoError(t, err)
	assert.Nil(t, fresh.FirstSeenAt, "current-hour flushes must not turn first-seen activity into historical activity")
	b, err := repo.GetBaseline(context.Background(), "a1", "new.exe", 10, ref.Truncate(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 0, b.HostActiveSlots)
	assert.Equal(t, 0, b.PresentSlots)
}

func TestBaselineCache_UsesEventHour(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	ref := time.Date(2026, 10, 15, 22, 5, 0, 0, time.UTC)
	seed(repo, ref, 1, 2, "x.exe")
	cache := baselines.NewBaselineCache(repo, time.Minute)
	b, err := cache.Lookup(context.Background(), "a1", "X.EXE", ref)
	require.NoError(t, err)
	assert.Equal(t, 22, b.HourOfDay)
	assert.Equal(t, 1, b.PresentSlots)
}

func TestNoopBaselineProvider_AlwaysNil(t *testing.T) {
	b, err := baselines.NoopBaselineProvider{}.Lookup(context.Background(), "a", "p", time.Now())
	assert.NoError(t, err)
	assert.Nil(t, b)
}

type uncertainCommitRepo struct {
	*baselines.InMemoryBaselineRepository
	tokens map[string]bool
	fail   bool
}

func (r *uncertainCommitRepo) AddBatchCounts(ctx context.Context, id string, counts []baselines.HourlyCount) error {
	if r.tokens[id] {
		return nil
	}
	r.tokens[id] = true
	if err := r.AddCounts(ctx, counts); err != nil {
		return err
	}
	if r.fail {
		r.fail = false
		return errors.New("commit succeeded but acknowledgement lost")
	}
	return nil
}
func TestAggregatorRetryDoesNotDuplicateUncertainCommit(t *testing.T) {
	r := &uncertainCommitRepo{InMemoryBaselineRepository: baselines.NewInMemoryBaselineRepository(), tokens: map[string]bool{}, fail: true}
	a := baselines.NewBaselineAggregator(r, 0, 0)
	in := baselines.AggregationInput{AgentID: "agent", ProcessName: "fixture.exe", ObservedAt: time.Now()}
	a.Record(in)
	a.Flush(context.Background())
	a.Record(in)
	a.Flush(context.Background())
	require.Len(t, r.Buckets(), 1)
	require.Equal(t, 2, r.Buckets()[0].Count)
	require.Len(t, r.tokens, 2, "new observations must use a distinct token")
}
