package actiongate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEndpointMutationWaitCancelsWithoutLosingOwner(t *testing.T) {
	g := New()
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := g.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if len(g.token) != 1 {
		t.Fatal("cancelled waiter released another action")
	}
	release()
	release()
	if next, err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		next()
	}
}
