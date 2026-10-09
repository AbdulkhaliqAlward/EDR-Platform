package kafka

import (
	"sort"
	"sync"

	"github.com/segmentio/kafka-go"
)

// offsetTracker implements at-least-once commit semantics for a consumer
// whose messages are processed concurrently and complete out of order.
//
// For every partition it keeps the in-flight offsets in ascending order.
// When a message completes, the head of the queue is advanced over every
// completed entry; the last entry passed is the highest offset below which
// everything has been processed, and is the only one that may be committed.
// A crash therefore re-delivers unfinished messages instead of skipping them.
type offsetTracker struct {
	mu    sync.Mutex
	parts map[int]*partitionQueue
}

type trackedMsg struct {
	msg  kafka.Message
	done bool
}

type partitionQueue struct {
	entries []*trackedMsg         // ascending by offset
	byOff   map[int64]*trackedMsg // offset → entry
}

func newOffsetTracker() *offsetTracker {
	return &offsetTracker{parts: make(map[int]*partitionQueue)}
}

// add registers a fetched message as in flight. Fetches from several
// goroutines can register a partition's offsets out of order, so the entry
// is inserted at its sorted position (almost always the tail).
func (t *offsetTracker) add(msg kafka.Message) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pq := t.parts[msg.Partition]
	if pq == nil {
		pq = &partitionQueue{byOff: make(map[int64]*trackedMsg)}
		t.parts[msg.Partition] = pq
	}
	if _, dup := pq.byOff[msg.Offset]; dup {
		return // re-delivery after a rebalance: already tracked
	}
	// Keep commit metadata only, not multi-megabyte event payloads during an outage.
	e := &trackedMsg{msg: kafka.Message{Topic: msg.Topic, Partition: msg.Partition, Offset: msg.Offset}}
	pq.byOff[msg.Offset] = e
	n := len(pq.entries)
	if n == 0 || pq.entries[n-1].msg.Offset < msg.Offset {
		pq.entries = append(pq.entries, e)
		return
	}
	i := sort.Search(n, func(i int) bool { return pq.entries[i].msg.Offset > msg.Offset })
	pq.entries = append(pq.entries, nil)
	copy(pq.entries[i+1:], pq.entries[i:])
	pq.entries[i] = e
}

// done marks a message processed and returns the message to commit, if the
// contiguous processed prefix of its partition advanced.
func (t *offsetTracker) done(msg kafka.Message) (kafka.Message, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pq := t.parts[msg.Partition]
	if pq == nil {
		return kafka.Message{}, false
	}
	e := pq.byOff[msg.Offset]
	if e == nil {
		return kafka.Message{}, false
	}
	e.done = true

	var commit *trackedMsg
	i := 0
	for i < len(pq.entries) && pq.entries[i].done {
		commit = pq.entries[i]
		delete(pq.byOff, commit.msg.Offset)
		i++
	}
	if commit == nil {
		return kafka.Message{}, false
	}
	pq.entries = pq.entries[i:]
	return commit.msg, true
}

// inFlight returns the number of tracked, not yet committed messages.
func (t *offsetTracker) inFlight() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, pq := range t.parts {
		n += len(pq.entries)
	}
	return n
}
