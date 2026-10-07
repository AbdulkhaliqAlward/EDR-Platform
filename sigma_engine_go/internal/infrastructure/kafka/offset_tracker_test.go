package kafka

import (
	"testing"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
)

func msgAt(p int, off int64) kafka.Message { return kafka.Message{Partition: p, Offset: off} }

func TestOffsetTracker_CommitsOnlyContiguousPrefix(t *testing.T) {
	tr := newOffsetTracker()
	for off := int64(10); off <= 13; off++ {
		tr.add(msgAt(0, off))
	}

	// Out-of-order completion: 12 then 11 finish before 10.
	_, ok := tr.done(msgAt(0, 12))
	assert.False(t, ok, "12 cannot be committed while 10 and 11 are in flight")
	_, ok = tr.done(msgAt(0, 11))
	assert.False(t, ok)

	c, ok := tr.done(msgAt(0, 10))
	assert.True(t, ok)
	assert.Equal(t, int64(12), c.Offset, "completing 10 releases the whole prefix 10..12")
	assert.Equal(t, 1, tr.inFlight())

	c, ok = tr.done(msgAt(0, 13))
	assert.True(t, ok)
	assert.Equal(t, int64(13), c.Offset)
	assert.Equal(t, 0, tr.inFlight())
}

func TestOffsetTracker_PartitionsIndependent(t *testing.T) {
	tr := newOffsetTracker()
	tr.add(msgAt(0, 1))
	tr.add(msgAt(1, 1))
	_, ok := tr.done(msgAt(1, 1))
	assert.True(t, ok, "a slow partition 0 must not block partition 1")
}

func TestOffsetTracker_OutOfOrderRegistration(t *testing.T) {
	// Two fetch goroutines can register offsets of one partition out of order.
	tr := newOffsetTracker()
	tr.add(msgAt(0, 6))
	tr.add(msgAt(0, 5))
	_, ok := tr.done(msgAt(0, 6))
	assert.False(t, ok, "5 is still in flight, so 6 must not be committed")
	c, ok := tr.done(msgAt(0, 5))
	assert.True(t, ok)
	assert.Equal(t, int64(6), c.Offset)
}

func TestOffsetTracker_DuplicateAndUnknownAreSafe(t *testing.T) {
	tr := newOffsetTracker()
	tr.add(msgAt(0, 1))
	tr.add(msgAt(0, 1)) // re-delivery
	assert.Equal(t, 1, tr.inFlight())
	_, ok := tr.done(msgAt(0, 99))
	assert.False(t, ok)
	_, ok = tr.done(msgAt(3, 1))
	assert.False(t, ok)
}
