// Package processlineage retains measured process generations and verified
// parent generations. A PID alone is never a process identity.
package processlineage

import (
	"sort"
	"sync"
	"time"
)

type Identity struct {
	PID     uint32
	Started int64 // measured Unix nanoseconds; Windows values have 100 ns precision
}

type entry struct {
	parent Identity
	seen   time.Time
}

type Tree struct {
	Found       bool
	Complete    bool       // false after gaps, eviction, or starts preceding collection
	Descendants []Identity // deepest first, with exact process generations
}

type Store struct {
	mu            sync.Mutex
	entries       map[Identity]entry
	limit         int
	ttl           time.Duration
	coverageStart time.Time
	lastGap       time.Time
}

var Default = New(65536, 10*time.Minute)

func New(limit int, ttl time.Duration) *Store {
	if limit < 1 {
		limit = 1
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Store{entries: make(map[Identity]entry), limit: limit, ttl: ttl}
}

// BeginCoverage must run after a real event session starts. Restarting a
// session invalidates completeness for roots created before that restart.
func (s *Store) BeginCoverage(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coverageStart = at
	s.lastGap = at
}

func (s *Store) Gap(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if at.After(s.lastGap) {
		s.lastGap = at
	}
}

// Record accepts only measured identities. The caller must verify that the
// supplied parent generation existed when this child was born. Missing or
// uncertain parents are represented by a zero Identity, never a guessed PID.
func (s *Store) Record(id, parent Identity, at time.Time) {
	if id.PID <= 4 || id.Started <= 0 {
		return
	}
	if parent.PID == id.PID || parent.Started > id.Started || parent.Started <= 0 {
		parent = Identity{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.entries[id]; ok {
		if old.parent.Started != 0 {
			parent = old.parent
		}
		s.entries[id] = entry{parent: parent, seen: at}
		return
	}
	if len(s.entries) >= s.limit {
		s.prune(at)
		if len(s.entries) >= s.limit {
			var oldest Identity
			var when time.Time
			for k, e := range s.entries {
				if when.IsZero() || e.seen.Before(when) {
					oldest, when = k, e.seen
				}
			}
			delete(s.entries, oldest)
			s.lastGap = at
		}
	}
	s.entries[id] = entry{parent: parent, seen: at}
}

func (s *Store) prune(now time.Time) {
	for id, e := range s.entries {
		if now.Sub(e.seen) > s.ttl {
			delete(s.entries, id)
			s.lastGap = now
		}
	}
}

func (s *Store) Tree(root Identity, now time.Time) Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	_, found := s.entries[root]
	out := Tree{Found: found, Complete: found && !s.coverageStart.IsZero() &&
		root.Started >= s.coverageStart.UnixNano() && root.Started >= s.lastGap.UnixNano()}
	if !found {
		return out
	}
	children := make(map[Identity][]Identity)
	for id, e := range s.entries {
		if e.parent.Started > 0 {
			children[e.parent] = append(children[e.parent], id)
		}
	}
	seen := map[Identity]bool{root: true}
	var visit func(Identity)
	visit = func(id Identity) {
		cs := children[id]
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].Started == cs[j].Started {
				return cs[i].PID < cs[j].PID
			}
			return cs[i].Started < cs[j].Started
		})
		for _, child := range cs {
			if seen[child] {
				continue
			}
			seen[child] = true
			visit(child)
			out.Descendants = append(out.Descendants, child)
		}
	}
	visit(root)
	return out
}
