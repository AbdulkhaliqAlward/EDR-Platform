package queue

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/edr-platform/win-agent/internal/pb"
)

func TestPeekOldest_CorruptFileDoesNotBlockQueue(t *testing.T) {
	dir := t.TempDir()
	q := NewDiskQueue(dir, 10)

	// A corrupt file sorted first (older timestamp prefix) used to make
	// PeekOldest fail forever, stalling all later batches.
	if err := os.WriteFile(filepath.Join(dir, "0_corrupt.bin"), []byte{0xff, 0xff, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(&pb.EventBatch{BatchId: "good"}); err != nil {
		t.Fatal(err)
	}

	b, name, err := q.PeekOldest()
	if err != nil || b == nil || b.GetBatchId() != "good" {
		t.Fatalf("expected the good batch, got batch=%v name=%q err=%v", b, name, err)
	}
	if _, err := os.Stat(filepath.Join(dir, deadLetterDir, "0_corrupt.bin")); err != nil {
		t.Fatalf("corrupt file should be retained in the dead-letter folder: %v", err)
	}
	if q.FileCount() != 1 {
		t.Fatalf("dead-lettered files must not count as queue depth, got %d", q.FileCount())
	}
}

func TestDeadLetter_MovesFileOutOfQueue(t *testing.T) {
	dir := t.TempDir()
	q := NewDiskQueue(dir, 10)
	if err := q.Enqueue(&pb.EventBatch{BatchId: "poison"}); err != nil {
		t.Fatal(err)
	}
	_, name, err := q.PeekOldest()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.DeadLetter(name); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := q.PeekOldest(); b != nil {
		t.Fatal("dead-lettered batch must not be returned again")
	}
	if err := q.DeadLetter(`..\escape.bin`); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}
