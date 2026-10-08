package grpcclient

import (
	"context"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"testing"
	"time"
)

func TestResultRetryTransientRecoveryPermanentFailureAndCancellation(t *testing.T) {
	calls := 0
	if err := retryCommandResult(context.Background(), time.Millisecond, func(context.Context) error {
		calls++
		if calls < 3 {
			return grpcstatus.Error(codes.Unavailable, "synthetic")
		}
		return nil
	}); err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	calls = 0
	err := retryCommandResult(context.Background(), time.Millisecond, func(context.Context) error { calls++; return grpcstatus.Error(codes.PermissionDenied, "synthetic") })
	if grpcstatus.Code(err) != codes.PermissionDenied || calls != 1 {
		t.Fatal("permanent failure retried")
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	err = retryCommandResult(ctx, time.Hour, func(context.Context) error {
		calls++
		cancel()
		return grpcstatus.Error(codes.Unavailable, "synthetic")
	})
	if err != context.Canceled || calls != 1 {
		t.Fatal("cancellation did not stop retry")
	}
	calls = 0
	err = retryCommandResult(context.Background(), time.Millisecond, func(context.Context) error { calls++; return grpcstatus.Error(codes.Unavailable, "synthetic") })
	if err == nil || calls != 5 {
		t.Fatal("retry not bounded")
	}
}
