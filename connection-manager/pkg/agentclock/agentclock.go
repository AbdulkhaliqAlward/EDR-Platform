// Package agentclock keeps each agent's clock offset relative to the server
// and normalises agent-reported event times onto the server clock, so every
// timestamp in the platform is on one time base.
//
// The offset is measured from heartbeats (sent live every few seconds, never
// replayed): offset = server receive time − agent send time. That includes
// the one-way network latency, so differences below CorrectionThreshold are
// treated as "in sync" and timestamps are left untouched.
package agentclock

import (
	"sort"
	"sync"
	"time"
)

const (
	// CorrectionThreshold: smaller offsets are network latency, not skew.
	CorrectionThreshold = time.Second
	samplesKept         = 7
)

// Loader returns a persisted offset for an agent not yet measured since the
// server started (e.g. events arriving before the first heartbeat).
type Loader func(agentID string) (offset time.Duration, measuredAt time.Time, ok bool)

type state struct {
	samples    []time.Duration
	offset     time.Duration
	measuredAt time.Time
	loaded     bool // from the Loader, not measured by this process
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu     sync.Mutex
	agents map[string]*state
	load   Loader
	missed map[string]time.Time // negative cache for the Loader
	now    func() time.Time
}

// New creates a tracker; load may be nil.
func New(load Loader) *Tracker {
	return &Tracker{agents: map[string]*state{}, load: load, missed: map[string]time.Time{}, now: time.Now}
}

// Observe records one heartbeat and returns the agent's current offset
// (median of the recent samples, robust against one delayed heartbeat).
func (t *Tracker) Observe(agentID string, agentTime, serverTime time.Time) time.Duration {
	if t == nil || agentID == "" || agentTime.IsZero() {
		return 0
	}
	sample := serverTime.Sub(agentTime)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.agents[agentID]
	if s == nil || s.loaded {
		s = &state{}
		t.agents[agentID] = s
	}
	s.samples = append(s.samples, sample)
	if len(s.samples) > samplesKept {
		s.samples = s.samples[len(s.samples)-samplesKept:]
	}
	sorted := append([]time.Duration(nil), s.samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	s.offset = sorted[len(sorted)/2]
	s.measuredAt = serverTime
	delete(t.missed, agentID)
	return s.offset
}

// Offset returns the agent's offset and whether one is known.
func (t *Tracker) Offset(agentID string) (time.Duration, bool) {
	if t == nil || agentID == "" {
		return 0, false
	}
	t.mu.Lock()
	if s := t.agents[agentID]; s != nil {
		off := s.offset
		t.mu.Unlock()
		return off, true
	}
	if at, miss := t.missed[agentID]; miss && t.now().Sub(at) < time.Minute {
		t.mu.Unlock()
		return 0, false
	}
	t.mu.Unlock()

	if t.load == nil {
		return 0, false
	}
	off, measuredAt, ok := t.load(agentID) // outside the lock (DB call)
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.agents[agentID]; s != nil { // a heartbeat won the race
		return s.offset, true
	}
	if !ok || t.now().Sub(measuredAt) > 24*time.Hour {
		t.missed[agentID] = t.now()
		return 0, false
	}
	t.agents[agentID] = &state{offset: off, measuredAt: measuredAt, loaded: true}
	return off, true
}

// Normalize converts an agent-clock RFC 3339 timestamp to the server clock.
// It returns the corrected timestamp and true only when a correction was
// applied (offset known and at least CorrectionThreshold).
func Normalize(ts string, offset time.Duration) (string, bool) {
	if offset > -CorrectionThreshold && offset < CorrectionThreshold {
		return ts, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ts, false
	}
	return t.Add(offset).UTC().Format(time.RFC3339Nano), true
}
