package agentclock

import (
	"testing"
	"time"
)

func TestObserveUsesMedianOfRecentHeartbeats(t *testing.T) {
	tr := New(nil)
	server := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	// Agent clock 5 minutes behind; one heartbeat delayed 3 s in the network.
	for i, lag := range []time.Duration{0, 40 * time.Millisecond, 3 * time.Second, 20 * time.Millisecond, 60 * time.Millisecond} {
		at := server.Add(time.Duration(i) * 10 * time.Second)
		tr.Observe("a1", at.Add(-5*time.Minute).Add(-lag), at)
	}
	off, ok := tr.Offset("a1")
	if !ok || off != 5*time.Minute+40*time.Millisecond {
		t.Fatalf("offset = %v %v, want 5m0.04s (median, delayed heartbeat ignored)", off, ok)
	}
	if _, ok := tr.Offset("unknown"); ok {
		t.Fatal("unmeasured agent reported an offset")
	}
}

func TestNormalize(t *testing.T) {
	ts := "2026-10-12T09:55:00.123456789Z"
	if got, changed := Normalize(ts, 300*time.Millisecond); changed || got != ts {
		t.Fatalf("latency-sized offset must not change timestamps: %v %v", got, changed)
	}
	got, changed := Normalize(ts, 5*time.Minute)
	if !changed || got != "2026-10-12T10:00:00.123456789Z" {
		t.Fatalf("behind clock: %v %v", got, changed)
	}
	got, _ = Normalize("2026-10-12T13:00:00+03:00", -2*time.Hour) // agent 2h ahead, local offset
	if got != "2026-10-12T08:00:00Z" {
		t.Fatalf("ahead clock with zone: %v", got)
	}
	if got, changed := Normalize("not-a-time", time.Hour); changed || got != "not-a-time" {
		t.Fatal("unparseable timestamp modified")
	}
}

func TestLoaderFallbackAndHeartbeatPrecedence(t *testing.T) {
	calls := 0
	now := time.Now()
	tr := New(func(id string) (time.Duration, time.Time, bool) {
		calls++
		if id == "persisted" {
			return 90 * time.Second, now.Add(-time.Hour), true
		}
		if id == "stale" {
			return time.Hour, now.Add(-48 * time.Hour), true
		}
		return 0, time.Time{}, false
	})
	if off, ok := tr.Offset("persisted"); !ok || off != 90*time.Second {
		t.Fatalf("persisted offset not used before first heartbeat: %v %v", off, ok)
	}
	if _, ok := tr.Offset("stale"); ok {
		t.Fatal("offset measured 2 days ago must not be trusted")
	}
	before := calls
	tr.Offset("missing")
	tr.Offset("missing")
	if calls != before+1 {
		t.Fatalf("negative result not cached: %d loader calls", calls-before)
	}
	// A live heartbeat replaces the persisted value.
	tr.Observe("persisted", now.Add(-2*time.Second), now)
	if off, _ := tr.Offset("persisted"); off != 2*time.Second {
		t.Fatalf("heartbeat did not replace persisted offset: %v", off)
	}
}
