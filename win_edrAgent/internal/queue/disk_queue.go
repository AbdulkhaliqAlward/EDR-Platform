// Package queue provides a concurrent-safe disk-backed queue for telemetry batches (WAL).
package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/edr-platform/win-agent/internal/pb"
)

const (
	fileExt = ".bin"
)

// DataEncryptor is an optional interface for data-at-rest encryption.
// When set on DiskQueue, all data is encrypted before writing and decrypted on read.
type DataEncryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// DiskQueue is a concurrent-safe disk queue that stores EventBatch protos as binary files.
// Files are named <unix_nano>_<batch_id>.bin for chronological ordering. Oldest files are
// evicted when total size would exceed MaxQueueSizeMB.
type DiskQueue struct {
	dir          string
	maxSizeMB    int
	maxSizeBytes int64
	mu           sync.Mutex
	encryptor    DataEncryptor // optional, nil = no encryption
}

// NewDiskQueue creates a new disk queue. dir must exist; maxSizeMB is the quota in megabytes.
func NewDiskQueue(dir string, maxSizeMB int) *DiskQueue {
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 500 * 1024 * 1024
	}
	return &DiskQueue{
		dir:          dir,
		maxSizeMB:    maxSizeMB,
		maxSizeBytes: maxBytes,
	}
}

// SetEncryptor enables data-at-rest encryption for all queue I/O.
func (q *DiskQueue) SetEncryptor(enc DataEncryptor) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.encryptor = enc
}

// sanitizeBatchID returns a filesystem-safe name from batch ID (no path separators or reserved chars).
func sanitizeBatchID(batchID string) string {
	s := batchID
	for _, c := range []string{`\`, `/`, ":", "*", "?", "\"", "<", ">", "|"} {
		s = strings.ReplaceAll(s, c, "_")
	}
	if s == "" {
		s = "batch"
	}
	return s
}

// totalSizeBytes returns the sum of sizes of all .bin files in the queue dir under mu.
func (q *DiskQueue) totalSizeBytes() (int64, []string, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0, nil, err
	}
	var total int64
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), fileExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
		names = append(names, e.Name())
	}
	sort.Strings(names) // chronological by filename (unix nano prefix)
	return total, names, nil
}

// Enqueue serializes the batch to disk. If adding the file would exceed MaxQueueSizeMB,
// oldest file(s) are removed first (FIFO).
func (q *DiskQueue) Enqueue(batch *pb.EventBatch) error {
	if batch == nil {
		return fmt.Errorf("batch is nil")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	data, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	// Encrypt data-at-rest if encryptor is available.
	if q.encryptor != nil {
		data, err = q.encryptor.Encrypt(data)
		if err != nil {
			return fmt.Errorf("encrypt batch: %w", err)
		}
	}

	size := int64(len(data))

	// Enforce quota: remove oldest files until we're under limit after adding this file
	for {
		total, names, err := q.totalSizeBytes()
		if err != nil {
			return fmt.Errorf("read queue dir: %w", err)
		}
		if total+size <= q.maxSizeBytes {
			break
		}
		if len(names) == 0 {
			break
		}
		oldest := names[0]
		path := filepath.Join(q.dir, oldest)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("evict oldest %s: %w", oldest, err)
		}
	}

	ts := time.Now().UnixNano()
	safeID := sanitizeBatchID(batch.GetBatchId())
	finalName := fmt.Sprintf("%d_%s%s", ts, safeID, fileExt)
	finalPath := filepath.Join(q.dir, finalName)
	tmpPath := finalPath + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp queue file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp queue file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync temp queue file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp queue file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp to final queue file: %w", err)
	}
	return nil
}

// PeekOldest returns the oldest batch and its filename without removing it.
// Returns (nil, "", nil) when the queue is empty.
func (q *DiskQueue) PeekOldest() (*pb.EventBatch, string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	_, names, err := q.totalSizeBytes()
	if err != nil {
		return nil, "", fmt.Errorf("read queue dir: %w", err)
	}
	// A file that cannot be decrypted or decoded can never be sent; it is
	// moved to the dead-letter folder so it no longer blocks the head of the
	// queue (previously the processor retried the same file forever).
	var lastErr error
	for _, oldest := range names {
		path := filepath.Join(q.dir, oldest)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read queue file %s: %w", oldest, err)
		}

		// Decrypt data-at-rest if encryptor is available.
		if q.encryptor != nil {
			data, err = q.encryptor.Decrypt(data)
			if err != nil {
				lastErr = fmt.Errorf("decrypt queue file %s: %w", oldest, err)
				_ = q.deadLetterLocked(oldest)
				continue
			}
		}

		batch := &pb.EventBatch{}
		if err := proto.Unmarshal(data, batch); err != nil {
			lastErr = fmt.Errorf("unmarshal batch %s: %w", oldest, err)
			_ = q.deadLetterLocked(oldest)
			continue
		}
		return batch, oldest, nil
	}
	return nil, "", lastErr
}

// deadLetterDir is the queue subfolder for batches that cannot be delivered.
// They are retained (not deleted) for forensic recovery and excluded from
// the queue and its quota.
const deadLetterDir = "deadletter"

// DeadLetter moves a queued batch out of the delivery queue into the
// dead-letter folder (kept on disk, no longer retried).
func (q *DiskQueue) DeadLetter(filename string) error {
	if filename == "" || strings.ContainsAny(filename, `\/`) || filepath.Clean(filename) != filename {
		return fmt.Errorf("invalid filename for dead-letter")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.deadLetterLocked(filename)
}

func (q *DiskQueue) deadLetterLocked(filename string) error {
	dir := filepath.Join(q.dir, deadLetterDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Rename(filepath.Join(q.dir, filename), filepath.Join(dir, filename))
}

// Remove deletes the queue file by filename (base name only). The filename must not contain path separators.
func (q *DiskQueue) Remove(filename string) error {
	if filename == "" || strings.Contains(filename, string(os.PathSeparator)) || filepath.Clean(filename) != filename {
		return fmt.Errorf("invalid filename for remove")
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	path := filepath.Join(q.dir, filename)
	// Ensure path stays under q.dir (no path traversal)
	absDir, err := filepath.Abs(q.dir)
	if err != nil {
		return err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	sep := string(os.PathSeparator)
	if absPath == absDir || !strings.HasPrefix(absPath, absDir+sep) {
		return fmt.Errorf("filename is outside queue dir")
	}
	return os.Remove(path)
}

// FileCount returns the number of pending .bin files in the queue directory.
// This is used as the Queue Depth health metric — it reflects the actual
// backlog of unsent events (files awaiting delivery), not the in-memory
// buffer occupancy (which is always high under normal load).
func (q *DiskQueue) FileCount() int {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), fileExt) {
			count++
		}
	}
	return count
}

