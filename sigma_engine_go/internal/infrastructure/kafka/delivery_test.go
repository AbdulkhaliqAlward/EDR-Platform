package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
)

func TestDurableDeliveryRetriesEachStageWithoutRepeatingPersistence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writes, publishes := 0, 0
	created, err := persistAndPublish(ctx, func(context.Context) (bool, error) {
		writes++
		if writes == 1 {
			return false, errors.New("database unavailable")
		}
		return true, nil
	}, func(context.Context) error {
		require.Equal(t, 2, writes, "publication must follow persistence")
		publishes++
		if publishes == 1 {
			return errors.New("broker unavailable")
		}
		return nil
	}, nil)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, 2, writes)
	require.Equal(t, 2, publishes)
}

func TestDurableDeliveryCancellationCannotPublishUnpersistedAlert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	published := false
	_, err := persistAndPublish(ctx, func(context.Context) (bool, error) {
		cancel()
		return false, errors.New("database unavailable")
	}, func(context.Context) error { published = true; return nil }, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, published)
}

func TestConsumerRejectsNullAndNonObjectWithoutPanic(t *testing.T) {
	c := &EventConsumer{}
	for _, payload := range []string{"null", "[]", "42", "{invalid"} {
		_, err := c.parseMessage(kafka.Message{Value: []byte(payload)})
		require.Error(t, err, payload)
	}
}

func TestOffsetTrackerDoesNotRetainEventPayload(t *testing.T) {
	tracker := newOffsetTracker()
	tracker.add(kafka.Message{Partition: 1, Offset: 2, Value: make([]byte, 1024*1024)})
	require.Empty(t, tracker.parts[1].entries[0].msg.Value)
	msg, ok := tracker.done(kafka.Message{Partition: 1, Offset: 2})
	require.True(t, ok)
	require.Equal(t, int64(2), msg.Offset)
}
