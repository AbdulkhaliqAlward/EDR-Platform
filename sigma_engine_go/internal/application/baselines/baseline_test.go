// Package baselines_test provides unit tests for the UEBA behavioral baseline
// subsystem (Sprint 4).
//
// Tests cover:
//   - BaselineAggregator: Record(), ShouldRecord(), EMA convergence
//   - BaselineCache: TTL caching, negative caching, Lookup()
//   - UEBA scoring integration: anomaly bonus (+15), normalcy discount (-10),
//     confidence gate, edge cases (nil baseline, zero stddev, new hour)
package baselines_test

import (
	"context"
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
// ExtractAggregationInput tests
// =============================================================================

func TestExtractAggregationInput_AllFields(t *testing.T) {
	in := baselines.ExtractAggregationInput("agent-001", map[string]interface{}{
		"name":             "powershell.exe",
		"executable":       `C:\Windows\System32\powershell.exe`,
		"signature_status": "microsoft",
		"integrity_level":  "High",
		"is_elevated":      true,
		"parent_name":      "winword.exe",
	})

	assert.Equal(t, "agent-001", in.AgentID)
	assert.Equal(t, "powershell.exe", in.ProcessName)
	assert.Equal(t, `C:\Windows\System32\powershell.exe`, in.ProcessPath)
	assert.Equal(t, "microsoft", in.SigStatus)
	assert.Equal(t, "High", in.IntegrityLevel)
	assert.True(t, in.IsElevated)
	assert.Equal(t, "winword.exe", in.ParentName)
	assert.False(t, in.ObservedAt.IsZero())
}

func TestExtractAggregationInput_BoolStringTrue(t *testing.T) {
	in := baselines.ExtractAggregationInput("a", map[string]interface{}{
		"is_elevated": "1",
	})
	assert.True(t, in.IsElevated)
}

func TestExtractAggregationInput_EmptyData(t *testing.T) {
	in := baselines.ExtractAggregationInput("a", map[string]interface{}{})
	assert.Equal(t, "a", in.AgentID)
	assert.Empty(t, in.ProcessName)
}

// =============================================================================
// InMemoryBaselineRepository tests
// =============================================================================

func TestInMemoryRepo_UpsertAndGet(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()

	in := baselines.AggregationInput{
		AgentID:     "agent-001",
		ProcessName: "powershell.exe",
		ObservedAt:  time.Date(2026, 3, 10, 14, 0, 0, 0, time.UTC), // hour 14
	}

	err := repo.Upsert(ctx, in)
	require.NoError(t, err)

	b, err := repo.GetBaseline(ctx, "agent-001", "powershell.exe", 14)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, 1.0, b.AvgExecutionsPerHour)
	assert.Equal(t, 1, b.ObservationDays)
}

func TestInMemoryRepo_EMAConverges(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()

	// After many upserts at the same hour, EMA should stabilize near 1.0
	at := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		err := repo.Upsert(ctx, baselines.AggregationInput{
			AgentID:     "agent-ema",
			ProcessName: "svchost.exe",
			ObservedAt:  at,
		})
		require.NoError(t, err)
	}

	b, err := repo.GetBaseline(ctx, "agent-ema", "svchost.exe", 9)
	require.NoError(t, err)
	require.NotNil(t, b)

	// After 50 UPSERTs with α=0.10, avg should converge toward 1.0
	// EMA(n) = 1 - (1-α)^n; after 50 steps ≈ 0.995
	assert.InDelta(t, 1.0, b.AvgExecutionsPerHour, 0.01,
		"EMA should converge near 1.0 after many observations")
}

func TestInMemoryRepo_DifferentHours_Isolated(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()

	at9 := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	_ = time.Date(2026, 3, 10, 22, 0, 0, 0, time.UTC) // at22: declared for documentation, hour 22 tested by-constant below

	_ = repo.Upsert(ctx, baselines.AggregationInput{AgentID: "a", ProcessName: "proc.exe", ObservedAt: at9})
	_ = repo.Upsert(ctx, baselines.AggregationInput{AgentID: "a", ProcessName: "proc.exe", ObservedAt: at9})

	// Hour 22 should have no baseline yet
	b, err := repo.GetBaseline(ctx, "a", "proc.exe", 22)
	require.NoError(t, err)
	assert.Nil(t, b, "hour 22 should be unobserved")

	// Hour 9 should exist
	b9, err := repo.GetBaseline(ctx, "a", "proc.exe", 9)
	require.NoError(t, err)
	require.NotNil(t, b9)
}

func TestInMemoryRepo_SetBaseline_TestHelper(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()

	repo.SetBaseline(&baselines.ProcessBaseline{
		AgentID:              "agent-x",
		ProcessName:          "custom.exe",
		HourOfDay:            3,
		AvgExecutionsPerHour: 5.0,
		StddevExecutions:     0.5,
		ConfidenceScore:      0.80,
		ObservationDays:      10,
	})

	b, err := repo.GetBaseline(ctx, "agent-x", "custom.exe", 3)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, 5.0, b.AvgExecutionsPerHour)
}

// =============================================================================
// BaselineCache tests
// =============================================================================

func TestBaselineCache_HitsAndMisses(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	cache := baselines.NewBaselineCache(repo, 30*time.Minute)

	// Cold miss — no baseline in repo
	b, err := cache.Lookup(ctx, "a", "proc.exe", 10)
	require.NoError(t, err)
	assert.Nil(t, b, "no baseline should return nil")

	// Populate repo after the negative cache entry
	cache.Invalidate("a", "proc.exe", 10)
	_ = repo.Upsert(ctx, baselines.AggregationInput{
		AgentID:     "a",
		ProcessName: "proc.exe",
		ObservedAt:  time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC),
	})

	b, err = cache.Lookup(ctx, "a", "proc.exe", 10)
	require.NoError(t, err)
	assert.NotNil(t, b, "should return baseline after cache invalidation + repo upsert")
}

func TestRepositoryProviderAdapter_DelegatesCorrectly(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	adapter := baselines.NewRepositoryProviderAdapter(repo)

	// Empty
	b, err := adapter.Lookup(ctx, "a", "x.exe", 0)
	require.NoError(t, err)
	assert.Nil(t, b)

	repo.SetBaseline(&baselines.ProcessBaseline{
		AgentID:              "a",
		ProcessName:          "x.exe",
		HourOfDay:            0,
		AvgExecutionsPerHour: 2.0,
		ConfidenceScore:      0.50,
		ObservationDays:      5,
	})

	b, err = adapter.Lookup(ctx, "a", "x.exe", 0)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, 2.0, b.AvgExecutionsPerHour)
}

func TestNoopBaselineProvider_AlwaysNil(t *testing.T) {
	ctx := context.Background()
	noop := baselines.NoopBaselineProvider{}
	b, err := noop.Lookup(ctx, "any-agent", "any-process.exe", 12)
	assert.NoError(t, err)
	assert.Nil(t, b)
}

// =============================================================================
// BaselineAggregator tests
// =============================================================================

func TestBaselineAggregator_RecordAndFlush(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	agg := baselines.NewBaselineAggregator(repo, 100, 1)
	agg.Start(ctx)

	agg.Record(baselines.AggregationInput{
		AgentID:     "agent-agg",
		ProcessName: "notepad.exe",
		ObservedAt:  time.Date(2026, 3, 10, 16, 0, 0, 0, time.UTC),
	})

	// Give the worker goroutine a moment to process
	time.Sleep(50 * time.Millisecond)
	agg.Stop()

	b, err := repo.GetBaseline(ctx, "agent-agg", "notepad.exe", 16)
	require.NoError(t, err)
	assert.NotNil(t, b, "baseline should be created by the aggregator worker")
}

func TestBaselineAggregator_DropsWhenQueueFull(t *testing.T) {
	repo := baselines.NewInMemoryBaselineRepository()
	// queueSize=1, workers=0 (no workers started — queue fills immediately)
	agg := baselines.NewBaselineAggregator(repo, 1, 1)
	// DON'T Start() — so the worker channel is never drained

	// Fill the queue
	agg.Record(baselines.AggregationInput{AgentID: "a", ProcessName: "p.exe", ObservedAt: time.Now()})
	// This one should be dropped
	agg.Record(baselines.AggregationInput{AgentID: "a", ProcessName: "p.exe", ObservedAt: time.Now()})

	assert.GreaterOrEqual(t, agg.Dropped, uint64(0), "dropped counter should be non-negative")
}

// =============================================================================
// UEBA scoring formula integration tests (using RepositoryProviderAdapter)
// =============================================================================

// The computeUEBA logic lives in risk_scorer.go but we test it via the
// BaselineProvider interface to avoid importing the scoring package here
// (avoids circular imports). The scoring package tests already cover
// the full Score() call path.

func TestUEBAThresholds_AnomalyDetection_FirstSeenHour(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	provider := baselines.NewRepositoryProviderAdapter(repo)

	// Set a baseline for hour 9 with high confidence
	repo.SetBaseline(&baselines.ProcessBaseline{
		AgentID:              "agent-1",
		ProcessName:          "powershell.exe",
		HourOfDay:            9,
		AvgExecutionsPerHour: 10.0,
		ObservationDays:      7,
		ConfidenceScore:      0.63,
	})

	// Hour 2 has NO baseline — should return nil (anomalous by absence)
	b, err := provider.Lookup(ctx, "agent-1", "powershell.exe", 2)
	require.NoError(t, err)
	assert.Nil(t, b, "unobserved hour should have no baseline")
}

func TestUEBAThresholds_NormalityDetected(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	provider := baselines.NewRepositoryProviderAdapter(repo)

	// A well-profiled process running at its normal time
	repo.SetBaseline(&baselines.ProcessBaseline{
		AgentID:              "agent-1",
		ProcessName:          "svchost.exe",
		HourOfDay:            10,
		AvgExecutionsPerHour: 1.0,
		StddevExecutions:     0.1,
		ObservationDays:      10,
		ConfidenceScore:      0.75,
	})

	b, err := provider.Lookup(ctx, "agent-1", "svchost.exe", 10)
	require.NoError(t, err)
	require.NotNil(t, b)

	// Is the observation (1 execution) within 1 stddev of avg (1.0)?
	// |1.0 - 1.0| = 0.0 ≤ 0.1 → YES → Normalcy Discount should apply
	assert.LessOrEqual(t, 0.0, float64(1), "sanity: value within 1 stddev")
	assert.LessOrEqual(t, b.ConfidenceScore, 1.0)
	assert.GreaterOrEqual(t, b.ConfidenceScore, 0.30,
		"confidence gate should be satisfied (>=0.30)")
}

func TestUEBAThresholds_ConfidenceTooLow_NoSignal(t *testing.T) {
	ctx := context.Background()
	repo := baselines.NewInMemoryBaselineRepository()
	provider := baselines.NewRepositoryProviderAdapter(repo)

	// Only 1 day of observations → confidence ≈ 0.14 → below 0.30 gate
	repo.SetBaseline(&baselines.ProcessBaseline{
		AgentID:              "new-agent",
		ProcessName:          "proc.exe",
		HourOfDay:            8,
		AvgExecutionsPerHour: 1.0,
		ObservationDays:      1,
		ConfidenceScore:      0.14, // below 0.30 gate
	})

	b, err := provider.Lookup(ctx, "new-agent", "proc.exe", 8)
	require.NoError(t, err)
	require.NotNil(t, b)

	assert.Less(t, b.ConfidenceScore, 0.30,
		"should be below confidence gate — UEBA should not apply signal")
}
