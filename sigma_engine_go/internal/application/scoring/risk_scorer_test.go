package scoring_test

import (
	"context"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/edr-platform/sigma-engine/internal/application/scoring"
	"github.com/edr-platform/sigma-engine/internal/domain"
	infracache "github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedContextProvider struct {
	factors scoring.ContextFactors
}

func (f fixedContextProvider) Resolve(_ context.Context, _, _, _ string) (scoring.ContextFactors, error) {
	return f.factors, nil
}

// =============================================================================
// SuspicionMatrix Tests
// =============================================================================

func TestSuspicionMatrix_KnownCriticalPairs(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	criticalPairs := [][2]string{
		{"winword.exe", "powershell.exe"},
		{"winword.exe", "cmd.exe"},
		{"outlook.exe", "powershell.exe"},
		{"excel.exe", "powershell.exe"},
	}

	for _, pair := range criticalPairs {
		t.Run(pair[0]+"->"+pair[1], func(t *testing.T) {
			entry, ok := m.Lookup(pair[0], pair[1])
			require.True(t, ok, "Expected entry for %s→%s", pair[0], pair[1])
			assert.Equal(t, 40, entry.Bonus, "Critical pair should have bonus=40")
			assert.NotEmpty(t, entry.Rationale)
		})
	}
}

func TestSuspicionMatrix_WildcardProcesses(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	wildcards := []string{"mshta.exe", "regsvr32.exe"}
	for _, child := range wildcards {
		t.Run(child, func(t *testing.T) {
			entry, ok := m.LookupWildcard(child)
			require.True(t, ok, "Expected wildcard entry for %s", child)
			assert.Equal(t, 40, entry.Bonus)
		})
	}
}

func TestSuspicionMatrix_CaseInsensitivity(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	// All-caps
	entry, ok := m.Lookup("WINWORD.EXE", "POWERSHELL.EXE")
	require.True(t, ok)
	assert.Equal(t, 40, entry.Bonus)

	// Mixed case
	entry, ok = m.Lookup("WinWord.Exe", "PowerShell.exe")
	require.True(t, ok)
	assert.Equal(t, 40, entry.Bonus)
}

func TestSuspicionMatrix_UnknownPairReturnsNoEntry(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	_, ok := m.Lookup("chrome.exe", "notepad.exe")
	assert.False(t, ok, "Unknown pair should return false")
}

func TestSuspicionMatrix_ComputeBonus_EmptyChain(t *testing.T) {
	m := scoring.NewSuspicionMatrix()
	bonus, level := m.ComputeBonus(nil)
	assert.Equal(t, 0, bonus)
	assert.Equal(t, "none", level)
}

func TestSuspicionMatrix_ComputeBonus_HighSuspicionChain(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	chain := []*infracache.ProcessLineageEntry{
		{PID: 4, Name: "powershell.exe"},
		{PID: 3, Name: "winword.exe"},
	}

	bonus, level := m.ComputeBonus(chain)
	assert.Equal(t, 40, bonus, "winword->powershell should give +40")
	assert.Equal(t, "critical", level)
}

func TestSuspicionMatrix_ComputeBonus_DeepChainUsesHighestBonus(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	// 3-hop chain: powershell → cmd → winword
	// Two suspicious pairs exist: winword→cmd (+40) and cmd→powershell (+30)
	// Expect the highest: +40
	chain := []*infracache.ProcessLineageEntry{
		{PID: 4, Name: "powershell.exe"},
		{PID: 3, Name: "cmd.exe"},
		{PID: 2, Name: "winword.exe"},
	}

	bonus, level := m.ComputeBonus(chain)
	assert.Equal(t, 40, bonus, "Should pick the highest bonus from the chain")
	assert.Equal(t, "critical", level)
}

func TestSuspicionMatrix_ComputeBonus_WildcardHit(t *testing.T) {
	m := scoring.NewSuspicionMatrix()

	// mshta.exe as the target process (chain[0])
	chain := []*infracache.ProcessLineageEntry{
		{PID: 10, Name: "mshta.exe"},
		{PID: 1, Name: "explorer.exe"},
	}

	bonus, level := m.ComputeBonus(chain)
	assert.Equal(t, 40, bonus, "mshta.exe wildcard should give +40")
	assert.Equal(t, "critical", level)
}

func TestSuspicionMatrix_HasReasonableSize(t *testing.T) {
	m := scoring.NewSuspicionMatrix()
	// Ensure the matrix was actually populated
	assert.GreaterOrEqual(t, m.Size(), 30,
		"Matrix should have at least 30 entries covering major LOLBin patterns")
}

// =============================================================================
// BurstTracker Tests
// =============================================================================

func TestInMemoryBurstTracker_FirstHitReturns1(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	ctx := context.Background()

	count, err := bt.IncrAndGet(ctx, "agent-1", "process_creation")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestInMemoryBurstTracker_CumulativeIncrement(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	ctx := context.Background()

	for i := 1; i <= 15; i++ {
		count, err := bt.IncrAndGet(ctx, "agent-1", "process_creation")
		require.NoError(t, err)
		assert.Equal(t, int64(i), count, "Count should be %d on iteration %d", i, i)
	}
}

func TestInMemoryBurstTracker_DifferentCategoriesAreIndependent(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	ctx := context.Background()

	_, _ = bt.IncrAndGet(ctx, "agent-1", "process_creation")
	_, _ = bt.IncrAndGet(ctx, "agent-1", "process_creation")
	_, _ = bt.IncrAndGet(ctx, "agent-1", "network_connection") // different category

	catA, _ := bt.Get(ctx, "agent-1", "process_creation")
	catB, _ := bt.Get(ctx, "agent-1", "network_connection")

	assert.Equal(t, int64(2), catA)
	assert.Equal(t, int64(1), catB)
}

func TestInMemoryBurstTracker_TTLExpiry(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(50 * time.Millisecond)
	ctx := context.Background()

	_, _ = bt.IncrAndGet(ctx, "agent-1", "proc")
	_, _ = bt.IncrAndGet(ctx, "agent-1", "proc")

	time.Sleep(100 * time.Millisecond)

	// After TTL, next increment should reset to 1
	count, err := bt.IncrAndGet(ctx, "agent-1", "proc")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "Counter should reset after TTL")
}

func TestInMemoryBurstTracker_Reset(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	ctx := context.Background()

	_, _ = bt.IncrAndGet(ctx, "agent-1", "proc")
	_, _ = bt.IncrAndGet(ctx, "agent-1", "proc")

	require.NoError(t, bt.Reset(ctx, "agent-1", "proc"))

	count, _ := bt.Get(ctx, "agent-1", "proc")
	assert.Equal(t, int64(0), count, "Count should be 0 after reset")
}

func TestInMemoryBurstTracker_GetReturns0OnMiss(t *testing.T) {
	bt := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	ctx := context.Background()

	count, err := bt.Get(ctx, "agent-x", "never-seen")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// =============================================================================
// RiskScorer Tests — Score Component Isolation
// =============================================================================

// makeMatchResult creates a minimal EventMatchResult for testing.
func makeMatchResult(t *testing.T, severity domain.Severity) *domain.EventMatchResult {
	t.Helper()
	cat := "process_creation"
	rule := &domain.SigmaRule{
		ID:    "test-rule-001",
		Title: "Test Rule",
		Level: severity.String(),
	}
	rule.LogSource.Category = &cat

	event := &domain.LogEvent{RawData: map[string]interface{}{}}
	mr := domain.NewEventMatchResult(event)
	mr.AddMatch(rule, 0.85, map[string]interface{}{"Image": "powershell.exe"}, []string{"selection"})
	return mr
}

func TestRiskScorer_BaseScore_InformationalIs10(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityInformational)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event:       &domain.LogEvent{RawData: map[string]interface{}{}},
		AgentID:     "test-agent",
	})

	require.NoError(t, err)
	assert.Equal(t, 10, out.Snapshot.ScoreBreakdown.BaseScore,
		"Informational severity base score should be 10")
}

func TestRiskScorer_BaseScore_CriticalIs85(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityCritical)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event:       &domain.LogEvent{RawData: map[string]interface{}{}},
		AgentID:     "test-agent",
	})

	require.NoError(t, err)
	assert.Equal(t, 85, out.Snapshot.ScoreBreakdown.BaseScore)
}

func TestRiskScorer_PrivilegeBonus_SystemSID(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityMedium)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"user_sid":        "S-1-5-18", // Local System
			"integrity_level": "System",
			"is_elevated":     true,
		}},
		AgentID: "test-agent",
	})

	require.NoError(t, err)
	assert.Greater(t, out.Snapshot.ScoreBreakdown.PrivilegeBonus, 0,
		"SYSTEM SID should produce a positive privilege bonus")
	assert.GreaterOrEqual(t, out.RiskScore, 45+20, // base + min system bonus
		"SYSTEM SID should increase overall risk score")
}

func TestRiskScorer_FPDiscount_MicrosoftSystem32(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityHigh)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"signature_status": "microsoft",
			"executable":       `C:\Windows\System32\svchost.exe`,
		}},
		AgentID: "test-agent",
	})

	require.NoError(t, err)
	assert.Greater(t, out.Snapshot.ScoreBreakdown.FPDiscount, 0,
		"Microsoft+System32 should produce a positive FP discount")
	// FP risk should be moderate (trusted but not zero)
	assert.Greater(t, out.FalsePositiveRisk, 0.0)
}

func TestRiskScorer_ScoreClamped0To100(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	// Maximum possible input: Critical severity + System SID + unsigned
	mr := makeMatchResult(t, domain.SeverityCritical)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"user_sid":         "S-1-5-18",
			"integrity_level":  "System",
			"is_elevated":      true,
			"signature_status": "unsigned",
		}},
		AgentID: "test-agent",
	})

	require.NoError(t, err)
	assert.LessOrEqual(t, out.RiskScore, 100, "Score must not exceed 100")
	assert.GreaterOrEqual(t, out.RiskScore, 0, "Score must not be negative")
}

func makeMatchResultForRule(t *testing.T, id string, severity domain.Severity) *domain.EventMatchResult {
	t.Helper()
	cat := "process_creation"
	rule := &domain.SigmaRule{ID: id, Title: "Rule " + id, Level: severity.String()}
	rule.LogSource.Category = &cat
	mr := domain.NewEventMatchResult(&domain.LogEvent{RawData: map[string]interface{}{}})
	mr.AddMatch(rule, 0.85, map[string]interface{}{"Image": "x.exe"}, []string{"selection"})
	return mr
}

// One rule repeating is a recurring pattern (often an automated benign task):
// it must not raise the score. Only distinct detections on a host count.
func TestRiskScorer_BurstBonus_NotForRepetition(t *testing.T) {
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineage := infracache.NewInMemoryLineageCache(5 * time.Minute)
	scorer := scoring.NewDefaultRiskScorer(lineage, burst, baselines.NoopBaselineProvider{})
	ctx := context.Background()
	event := &domain.LogEvent{RawData: map[string]interface{}{}}
	mr := makeMatchResult(t, domain.SeverityMedium)
	var out *scoring.ScoringOutput
	for i := 0; i < 10; i++ {
		var err error
		out, err = scorer.Score(ctx, scoring.ScoringInput{MatchResult: mr, Event: event, AgentID: "a"})
		require.NoError(t, err)
	}
	assert.Equal(t, 0, out.Snapshot.ScoreBreakdown.BurstBonus, "the same rule 10 times is not a burst")
}

func TestRiskScorer_BurstBonus_ForDistinctDetections(t *testing.T) {
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineage := infracache.NewInMemoryLineageCache(5 * time.Minute)
	scorer := scoring.NewDefaultRiskScorer(lineage, burst, baselines.NoopBaselineProvider{})
	ctx := context.Background()
	event := &domain.LogEvent{RawData: map[string]interface{}{}}
	var out *scoring.ScoringOutput
	for _, id := range []string{"r-a", "r-b", "r-c"} {
		var err error
		out, err = scorer.Score(ctx, scoring.ScoringInput{MatchResult: makeMatchResultForRule(t, id, domain.SeverityMedium), Event: event, AgentID: "a"})
		require.NoError(t, err)
	}
	assert.Equal(t, 10, out.Snapshot.ScoreBreakdown.BurstBonus, "3 distinct rules on one host in the window")

	// Another host is independent.
	other, err := scorer.Score(ctx, scoring.ScoringInput{MatchResult: makeMatchResultForRule(t, "r-a", domain.SeverityMedium), Event: event, AgentID: "b"})
	require.NoError(t, err)
	assert.Equal(t, 0, other.Snapshot.ScoreBreakdown.BurstBonus)
}

func TestRiskScorer_LOLBinGetsNoSignatureDiscount(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()
	mk := func(exe string) *scoring.ScoringOutput {
		out, err := scorer.Score(ctx, scoring.ScoringInput{
			MatchResult: makeMatchResult(t, domain.SeverityMedium),
			Event: &domain.LogEvent{RawData: map[string]interface{}{
				"signature_status": "microsoft", "executable": exe,
			}},
			AgentID: "x",
		})
		require.NoError(t, err)
		return out
	}
	lol := mk(`C:\Windows\System32\rundll32.exe`)
	assert.Equal(t, 0, lol.Snapshot.ScoreBreakdown.FPDiscount, "a Microsoft signature on a LOLBin is not evidence of benign use")
	normal := mk(`C:\Windows\System32\notepad.exe`)
	assert.Greater(t, normal.Snapshot.ScoreBreakdown.FPDiscount, 0)
}

func TestRiskScorer_SystemTokenCountedOnce(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	out, err := scorer.Score(context.Background(), scoring.ScoringInput{
		MatchResult: makeMatchResult(t, domain.SeverityMedium),
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"user_sid": "S-1-5-18", "integrity_level": "System", "signature_status": "microsoft",
			"executable": `C:\Windows\System32\svchost.exe`,
		}},
		AgentID: "x",
	})
	require.NoError(t, err)
	assert.Equal(t, 20, out.Snapshot.ScoreBreakdown.PrivilegeBonus, "SYSTEM SID and System integrity are one fact")
}

func TestRiskScorer_LineageBonus_CriticalChain(t *testing.T) {
	ctx := context.Background()
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineageCache := infracache.NewInMemoryLineageCache(5 * time.Minute)

	// Pre-populate: winword (pid=100) → powershell (pid=200)
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "agent-lob",
		PID:     100,
		PPID:    1,
		Name:    "winword.exe",
		SeenAt:  time.Now().Unix(),
	}))
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "agent-lob",
		PID:     200,
		PPID:    100,
		Name:    "powershell.exe",
		SeenAt:  time.Now().Unix(),
	}))

	scorer := scoring.NewDefaultRiskScorer(lineageCache, burst, baselines.NoopBaselineProvider{})
	mr := makeMatchResult(t, domain.SeverityHigh)
	event := &domain.LogEvent{RawData: map[string]interface{}{
		"pid": int64(200), // powershell's PID
	}}

	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event:       event,
		AgentID:     "agent-lob",
	})

	require.NoError(t, err)
	assert.Equal(t, 40, out.Snapshot.ScoreBreakdown.LineageBonus,
		"winword→powershell chain should give +40 lineage bonus")
	assert.Equal(t, "critical", out.Snapshot.LineageSuspicion)
	// Final score should be well above the base (65) alone
	assert.GreaterOrEqual(t, out.RiskScore, 90)
}

func TestRiskScorer_ContextSnapshot_FullyPopulated(t *testing.T) {
	ctx := context.Background()
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineage := infracache.NewInMemoryLineageCache(5 * time.Minute)
	scorer := scoring.NewDefaultRiskScorer(lineage, burst, baselines.NoopBaselineProvider{})

	mr := makeMatchResult(t, domain.SeverityHigh)
	event := &domain.LogEvent{RawData: map[string]interface{}{
		"name":             "powershell.exe",
		"executable":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"command_line":     "powershell.exe -enc JABjAG0A",
		"user_sid":         "S-1-5-18",
		"user_name":        "SYSTEM",
		"integrity_level":  "System",
		"is_elevated":      true,
		"signature_status": "microsoft",
	}}

	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event:       event,
		AgentID:     "agent-snap",
	})

	require.NoError(t, err)
	require.NotNil(t, out.Snapshot)

	snap := out.Snapshot
	assert.Equal(t, "powershell.exe", snap.ProcessName)
	assert.Equal(t, "S-1-5-18", snap.UserSID)
	assert.True(t, snap.IsElevated)
	assert.Equal(t, "System", snap.IntegrityLevel)
	assert.Equal(t, "microsoft", snap.SignatureStatus)
	assert.Equal(t, "test-rule-001", snap.RuleID)
	assert.False(t, snap.ScoredAt.IsZero())
	assert.Equal(t, 300, snap.BurstWindowSec)
	// ScoreBreakdown should be fully populated
	assert.Equal(t, out.RiskScore, snap.ScoreBreakdown.FinalScore)
}

func TestRiskScorer_NilMatchResult_ReturnsZero(t *testing.T) {
	scorer, _ := makeScorerWithNoCache()
	ctx := context.Background()

	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: nil,
		Event:       &domain.LogEvent{RawData: map[string]interface{}{}},
		AgentID:     "agent-nil",
	})

	require.NoError(t, err)
	assert.Equal(t, 0, out.RiskScore)
}

// =============================================================================
// End-to-End Scenario Tests
// =============================================================================

// TestScenario_WordMacroLOLBin simulates a classic Office macro → PowerShell attack.
// Expected: risk_score ≥ 90 (critical lineage + SYSTEM privilege + burst)
func TestScenario_WordMacroLOLBin(t *testing.T) {
	ctx := context.Background()
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineageCache := infracache.NewInMemoryLineageCache(5 * time.Minute)

	// Build lineage: winword (pid=1000) → powershell (pid=2000)
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "endpoint-01", PID: 1000, PPID: 4, Name: "winword.exe",
		SeenAt: time.Now().Unix(),
	}))
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "endpoint-01", PID: 2000, PPID: 1000, Name: "powershell.exe",
		SignatureStatus: "microsoft", IntegrityLevel: "High", IsElevated: true,
		SeenAt: time.Now().Unix(),
	}))

	scorer := scoring.NewDefaultRiskScorer(lineageCache, burst, baselines.NoopBaselineProvider{})
	mr := makeMatchResult(t, domain.SeverityHigh) // High severity Sigma rule matched

	event := &domain.LogEvent{RawData: map[string]interface{}{
		"pid":              int64(2000),
		"name":             "powershell.exe",
		"command_line":     "powershell.exe -enc JABjAG0AZAA=", // encoded command
		"signature_status": "microsoft",
		"integrity_level":  "High",
		"is_elevated":      true,
	}}

	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr, Event: event, AgentID: "endpoint-01",
	})

	require.NoError(t, err)
	t.Logf("LOLBin scenario score: %d | breakdown: %+v", out.RiskScore, out.Snapshot.ScoreBreakdown)

	assert.GreaterOrEqual(t, out.RiskScore, 90,
		"Word macro → PowerShell attack should score ≥ 90")
	assert.Equal(t, "critical", out.Snapshot.LineageSuspicion)
	assert.Equal(t, 40, out.Snapshot.ScoreBreakdown.LineageBonus)
}

// TestScenario_LegitSysadminPowerShell simulates a sysadmin running PowerShell
// directly from explorer. Expected: risk_score ≤ 50 (medium, no critical lineage)
func TestScenario_LegitSysadminPowerShell(t *testing.T) {
	ctx := context.Background()
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineageCache := infracache.NewInMemoryLineageCache(5 * time.Minute)

	// Explorer → PowerShell (medium lineage suspicion at most)
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "endpoint-02", PID: 3000, PPID: 1, Name: "explorer.exe", SeenAt: time.Now().Unix(),
	}))
	require.NoError(t, lineageCache.WriteEntry(ctx, &infracache.ProcessLineageEntry{
		AgentID: "endpoint-02", PID: 4000, PPID: 3000, Name: "powershell.exe",
		SignatureStatus: "microsoft", IntegrityLevel: "Medium", IsElevated: false,
		SeenAt: time.Now().Unix(),
	}))

	scorer := scoring.NewDefaultRiskScorer(lineageCache, burst, baselines.NoopBaselineProvider{})
	mr := makeMatchResult(t, domain.SeverityMedium) // Medium sigma rule

	event := &domain.LogEvent{RawData: map[string]interface{}{
		"pid":              int64(4000),
		"name":             "powershell.exe",
		"signature_status": "microsoft",
		"executable":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"integrity_level":  "Medium",
		"is_elevated":      false,
	}}

	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr, Event: event, AgentID: "endpoint-02",
	})

	require.NoError(t, err)
	t.Logf("Legit sysadmin score: %d | breakdown: %+v", out.RiskScore, out.Snapshot.ScoreBreakdown)

	// powershell.exe is a LOLBin: its Microsoft signature earns no discount,
	// but an interactive, non-elevated run must stay below the "high" band.
	// Routine use is lowered by UEBA normalcy and analyst exceptions instead.
	assert.Equal(t, 0, out.Snapshot.ScoreBreakdown.FPDiscount)
	assert.Less(t, out.RiskScore, 70, "legitimate sysadmin PowerShell must not reach the high band")
}

func TestRiskScorer_ContextFactors_AdjustFinalScore(t *testing.T) {
	scorer, _ := makeDefaultScorerWithNoCache()
	scorer.SetContextPolicyProvider(fixedContextProvider{
		factors: scoring.ContextFactors{
			UserRoleWeight:          1.2,
			DeviceCriticalityWeight: 1.3,
			NetworkAnomalyFactor:    1.1,
		},
	})
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityMedium)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"user_name": "svc-admin",
		}},
		AgentID: "ctx-agent",
	})

	require.NoError(t, err)
	require.NotNil(t, out.Snapshot)
	assert.Greater(t, out.Snapshot.ScoreBreakdown.ContextMultiplier, 1.0)
	assert.Equal(t, out.RiskScore, out.Snapshot.ScoreBreakdown.FinalScore)
	assert.GreaterOrEqual(t, out.Snapshot.ScoreBreakdown.ContextAdjustedScore, out.Snapshot.ScoreBreakdown.RawScore)
}

func TestRiskScorer_ContextFactors_AppearInSnapshot(t *testing.T) {
	scorer, _ := makeDefaultScorerWithNoCache()
	scorer.SetContextPolicyProvider(fixedContextProvider{
		factors: scoring.ContextFactors{
			UserRoleWeight:          0.9,
			DeviceCriticalityWeight: 1.0,
			NetworkAnomalyFactor:    1.2,
		},
	})
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityHigh)
	out, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event:       &domain.LogEvent{RawData: map[string]interface{}{}},
		AgentID:     "ctx-agent-2",
	})

	require.NoError(t, err)
	assert.InDelta(t, 0.9, out.Snapshot.UserRoleWeight, 0.001)
	assert.InDelta(t, 1.0, out.Snapshot.DeviceCriticalityWeight, 0.001)
	assert.InDelta(t, 1.2, out.Snapshot.NetworkAnomalyFactor, 0.001)
	assert.InDelta(t, out.Snapshot.ScoreBreakdown.ContextMultiplier, out.Snapshot.ContextMultiplier, 0.001)
}

func TestRiskScorer_ContextQualityFactor_ReducesScoreOnMissingFields(t *testing.T) {
	scorer, _ := makeDefaultScorerWithNoCache()
	scorer.SetContextPolicyProvider(fixedContextProvider{
		factors: scoring.ContextFactors{
			UserRoleWeight:          1.0,
			DeviceCriticalityWeight: 1.0,
			NetworkAnomalyFactor:    1.0,
		},
	})
	ctx := context.Background()

	mr := makeMatchResult(t, domain.SeverityHigh)
	outHighQuality, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"context_quality_score": 100.0,
		}},
		AgentID: "quality-agent",
	})
	require.NoError(t, err)

	outLowQuality, err := scorer.Score(ctx, scoring.ScoringInput{
		MatchResult: mr,
		Event: &domain.LogEvent{RawData: map[string]interface{}{
			"context_quality_score": 30.0,
			"missing_context_fields": []interface{}{
				"user_name", "ip_address",
			},
		}},
		AgentID: "quality-agent",
	})
	require.NoError(t, err)

	assert.InDelta(t, 1.0, outHighQuality.Snapshot.QualityFactor, 0.001)
	assert.InDelta(t, 0.90, outLowQuality.Snapshot.QualityFactor, 0.001)
	assert.LessOrEqual(t, outLowQuality.RiskScore, outHighQuality.RiskScore)
	require.NotEmpty(t, outLowQuality.Snapshot.Warnings)
}

// =============================================================================
// Helpers
// =============================================================================

func makeScorerWithNoCache() (scoring.RiskScorer, *scoring.InMemoryBurstTracker) {
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineage := infracache.NewNoopLineageCache()
	return scoring.NewDefaultRiskScorer(lineage, burst, baselines.NoopBaselineProvider{}), burst
}

func makeDefaultScorerWithNoCache() (*scoring.DefaultRiskScorer, *scoring.InMemoryBurstTracker) {
	burst := scoring.NewInMemoryBurstTracker(5 * time.Minute)
	lineage := infracache.NewNoopLineageCache()
	return scoring.NewDefaultRiskScorer(lineage, burst, baselines.NoopBaselineProvider{}), burst
}
