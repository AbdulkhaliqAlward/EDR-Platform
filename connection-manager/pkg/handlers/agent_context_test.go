package handlers

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNormalizeEventClockKeepsAgentTimeAndVerificationFields(t *testing.T) {
	ev := map[string]interface{}{
		"timestamp": "2026-10-12T09:50:00Z",
		"data":      map[string]interface{}{"process_start_time": "2026-10-12T09:49:59.5Z"},
	}
	normalizeEventClock(ev, 10*time.Minute) // agent clock 10 minutes behind
	if ev["timestamp"] != "2026-10-12T10:00:00Z" || ev["agent_timestamp"] != "2026-10-12T09:50:00Z" || ev["clock_offset_ms"] != int64(600000) {
		t.Fatalf("event not normalised: %v", ev)
	}
	// Agent-clock times used for PID identity on the endpoint stay untouched.
	if ev["data"].(map[string]interface{})["process_start_time"] != "2026-10-12T09:49:59.5Z" {
		t.Fatal("process_start_time must stay on the agent clock")
	}

	inSync := map[string]interface{}{"timestamp": "2026-10-12T10:00:00Z"}
	normalizeEventClock(inSync, 80*time.Millisecond)
	if _, changed := inSync["agent_timestamp"]; changed || inSync["timestamp"] != "2026-10-12T10:00:00Z" {
		t.Fatalf("network-latency offset changed the event: %v", inSync)
	}
}

func TestAgentContextRecorderFeedsClockWithoutDatabase(t *testing.T) {
	r := NewAgentContextRecorder(logrus.New(), nil, nil)
	now := time.Now()
	r.Observe("agent-1", "203.0.113.5:50123", now.Add(-3*time.Minute))
	off, ok := r.Clock().Offset("agent-1")
	if !ok || off < 3*time.Minute-time.Second || off > 3*time.Minute+time.Second {
		t.Fatalf("offset = %v %v, want ≈3m", off, ok)
	}
	r.mu.Lock()
	got := r.last["agent-1"]
	r.mu.Unlock()
	if got.addr != "203.0.113.5:50123" || got.loc.IP != "203.0.113.5" || got.loc.Scope != "unknown" {
		t.Fatalf("connection address not recorded: %+v", got)
	}
	var nilRecorder *AgentContextRecorder
	nilRecorder.Observe("x", "", now) // must not panic
	if nilRecorder.Clock() != nil {
		t.Fatal("nil recorder clock")
	}
}
