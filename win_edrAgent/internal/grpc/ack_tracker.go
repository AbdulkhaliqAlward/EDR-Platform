package grpcclient

import (
	"errors"
	"sync"
	"time"
)

// errNotAcknowledged reports that the server did not confirm a batch
// (timeout or stream loss). The batch must be retried from the disk queue.
var errNotAcknowledged = errors.New("batch not acknowledged by server")

// errTooManyPending reports that the in-flight confirmation window is full;
// the caller should persist the batch to the disk queue instead of sending.
var errTooManyPending = errors.New("too many batches awaiting acknowledgement")

// errStreamLost reports that the stream carrying a batch broke before its
// acknowledgement arrived (a connectivity failure, not a rejection).
var errStreamLost = errors.New("stream lost before acknowledgement")

// ackTracker tracks batches sent on the event stream until the server
// acknowledges them (CommandBatch.ack_batch_id). The server acknowledges a
// batch only after it is durably accepted (Kafka or its DB fallback), so a
// batch counts as delivered only once acknowledged.
//
// Two modes share one table:
//   - asynchronous (onUnconfirmed set): the batcher sends and moves on; if no
//     ACK arrives before the deadline, or the stream breaks, onUnconfirmed
//     receives the batch (the agent writes it to the disk queue).
//   - synchronous (done channel): the disk-queue processor waits for the ACK
//     before deleting the file.
type ackTracker struct {
	mu      sync.Mutex
	pending map[string]*pendingAck
	max     int
}

type pendingAck struct {
	batch         *EventBatch
	deadline      time.Time
	onUnconfirmed func(*EventBatch) // async mode
	done          chan error        // sync mode: nil = acked, else the failure reason
}

func newAckTracker(max int) *ackTracker {
	if max <= 0 {
		max = 256
	}
	return &ackTracker{pending: make(map[string]*pendingAck), max: max}
}

// register adds a batch before it is sent, so an ACK that races the send
// cannot be missed. It fails when the window is full.
func (t *ackTracker) register(id string, p *pendingAck) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[id]; !exists && len(t.pending) >= t.max {
		return errTooManyPending
	}
	t.pending[id] = p
	return nil
}

// cancel removes a registration whose send failed (the caller handles it).
func (t *ackTracker) cancel(id string) {
	t.mu.Lock()
	delete(t.pending, id)
	t.mu.Unlock()
}

// ack resolves a pending batch. Unknown IDs (late or duplicate ACKs) are ignored.
func (t *ackTracker) ack(id string) {
	t.mu.Lock()
	p := t.pending[id]
	delete(t.pending, id)
	t.mu.Unlock()
	if p != nil && p.done != nil {
		p.done <- nil
	}
}

// expire fails every batch whose deadline passed.
func (t *ackTracker) expire(now time.Time) {
	t.fail(func(p *pendingAck) bool { return now.After(p.deadline) }, errNotAcknowledged)
}

// failAll fails every pending batch (stream lost or shutting down).
func (t *ackTracker) failAll() {
	t.fail(func(*pendingAck) bool { return true }, errStreamLost)
}

func (t *ackTracker) fail(match func(*pendingAck) bool, reason error) {
	t.mu.Lock()
	var failed []*pendingAck
	for id, p := range t.pending {
		if match(p) {
			failed = append(failed, p)
			delete(t.pending, id)
		}
	}
	t.mu.Unlock()
	// Callbacks run outside the lock (they perform disk I/O).
	for _, p := range failed {
		if p.done != nil {
			p.done <- reason
		} else if p.onUnconfirmed != nil {
			p.onUnconfirmed(p.batch)
		}
	}
}

func (t *ackTracker) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}
