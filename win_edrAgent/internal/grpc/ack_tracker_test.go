package grpcclient

import (
	"errors"
	"testing"
	"time"

	pb "github.com/edr-platform/win-agent/internal/pb"
)

func batchWithID(id string) *EventBatch { return &pb.EventBatch{BatchId: id} }

func TestAckTracker_AckResolvesSyncWaiter(t *testing.T) {
	tr := newAckTracker(4)
	done := make(chan error, 1)
	if err := tr.register("b1", &pendingAck{batch: batchWithID("b1"), deadline: time.Now().Add(time.Minute), done: done}); err != nil {
		t.Fatal(err)
	}
	tr.ack("b1")
	if err := <-done; err != nil {
		t.Fatalf("expected ack, got %v", err)
	}
	if tr.len() != 0 {
		t.Fatal("acked batch must be removed")
	}
}

func TestAckTracker_ExpireSpillsAsyncAndFailsSync(t *testing.T) {
	tr := newAckTracker(4)
	var spilled []string
	past := time.Now().Add(-time.Second)
	_ = tr.register("async", &pendingAck{batch: batchWithID("async"), deadline: past, onUnconfirmed: func(b *EventBatch) { spilled = append(spilled, b.GetBatchId()) }})
	done := make(chan error, 1)
	_ = tr.register("sync", &pendingAck{batch: batchWithID("sync"), deadline: past, done: done})
	_ = tr.register("fresh", &pendingAck{batch: batchWithID("fresh"), deadline: time.Now().Add(time.Minute), onUnconfirmed: func(*EventBatch) { t.Error("fresh batch must not be spilled") }})

	tr.expire(time.Now())

	if len(spilled) != 1 || spilled[0] != "async" {
		t.Fatalf("expected async batch spilled, got %v", spilled)
	}
	if err := <-done; !errors.Is(err, errNotAcknowledged) {
		t.Fatalf("expired sync waiter should get errNotAcknowledged, got %v", err)
	}
	if tr.len() != 1 {
		t.Fatalf("only the fresh batch should remain, have %d", tr.len())
	}
}

func TestAckTracker_FailAllReportsStreamLoss(t *testing.T) {
	tr := newAckTracker(4)
	done := make(chan error, 1)
	_ = tr.register("s", &pendingAck{batch: batchWithID("s"), deadline: time.Now().Add(time.Minute), done: done})
	tr.failAll()
	if err := <-done; !errors.Is(err, errStreamLost) {
		t.Fatalf("stream loss must be distinguishable from non-acknowledgement, got %v", err)
	}
}

func TestAckTracker_WindowBoundAndLateAck(t *testing.T) {
	tr := newAckTracker(1)
	_ = tr.register("a", &pendingAck{batch: batchWithID("a"), deadline: time.Now().Add(time.Minute)})
	if err := tr.register("b", &pendingAck{batch: batchWithID("b"), deadline: time.Now().Add(time.Minute)}); !errors.Is(err, errTooManyPending) {
		t.Fatalf("expected window-full error, got %v", err)
	}
	tr.ack("unknown") // late/duplicate ACKs are ignored
	tr.cancel("a")
	if tr.len() != 0 {
		t.Fatal("cancel must remove the registration")
	}
}
