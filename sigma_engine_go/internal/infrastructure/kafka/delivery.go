package kafka

import (
	"context"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"time"
)

// persistAndPublish retains one alert while retrying; retries never repeat a
// successful persistence stage. Cancellation leaves the source offset unacked.
// Bounded workers and consumer in-flight limits keep outages from growing RAM.
func persistAndPublish(ctx context.Context, persist func(context.Context) (bool, error), publish func(context.Context) error, failed func(string, error)) (bool, error) {
	created := true
	retry := func(stage string, attempt func(context.Context) error) error {
		delay := 100 * time.Millisecond
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := attempt(attemptCtx)
			cancel()
			if err == nil {
				return nil
			}
			if failed != nil {
				failed(stage, err)
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			if delay < 2*time.Second {
				delay *= 2
				if delay > 2*time.Second {
					delay = 2 * time.Second
				}
			}
		}
	}
	if persist != nil {
		if err := retry("persist", func(ctx context.Context) error {
			var err error
			created, err = persist(ctx)
			return err
		}); err != nil {
			return false, err
		}
	}
	if err := retry("publish", publish); err != nil {
		return false, err
	}
	return created, nil
}

// Narrow contracts allow failure-path tests without a running broker/database.
type durableProducer interface {
	Start(context.Context) error
	Stop() error
	PublishSync(context.Context, *domain.Alert) error
	Metrics() ProducerMetrics
}
type durableAlertWriter interface {
	Persist(context.Context, *domain.Alert) (string, bool, error)
	UpdateCorrelationSummary(context.Context, string, map[string]any) error
	Metrics() database.AlertWriterMetrics
}

func (sc *suppressionCache) contains(key string) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	ts, ok := sc.entries[key]
	return ok && time.Since(ts) < sc.ttl
}
