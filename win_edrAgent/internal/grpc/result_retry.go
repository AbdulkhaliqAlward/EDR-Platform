package grpcclient

import (
	"context"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"time"
)

// Retry delivery of one immutable result; never re-execute the command.
func retryCommandResult(ctx context.Context, delay time.Duration, send func(context.Context) error) error {
	for attempt := 0; attempt < 5; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := send(ctx)
		if err == nil {
			return nil
		}
		switch grpcstatus.Code(err) {
		case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		default:
			return err
		}
		if attempt == 4 {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay *= 2
	}
	return ctx.Err()
}
