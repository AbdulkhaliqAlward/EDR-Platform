package playbook

import (
	"context"
	"errors"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/google/uuid"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDisabledAutomationSkipsPostIsolationTriage(t *testing.T) {
	e := &Engine{}
	called := false
	e.SetAutomationGate(func(ctx context.Context) bool {
		called = true
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("gate must use a bounded context")
		}
		return false
	})
	e.OnIsolationSucceeded(uuid.New())
	if !called {
		t.Fatal("legacy post-isolation path must check the authoritative automation switch")
	}
}

type resultCommands struct {
	repository.CommandRepository
	mu     sync.Mutex
	status models.CommandStatus
}

func (r *resultCommands) GetByID(context.Context, uuid.UUID) (*models.Command, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &models.Command{Status: r.status, ErrorMessage: "synthetic result"}, nil
}

func TestLegacyWaitRequiresTerminalAgentResult(t *testing.T) {
	r := &resultCommands{status: models.CommandStatusSent}
	e := &Engine{commandRepo: r, commandPoll: time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- e.awaitCommand(context.Background(), uuid.New(), time.Second) }()
	select {
	case err := <-done:
		t.Fatal("sent command incorrectly completed:", err)
	case <-time.After(10 * time.Millisecond):
	}
	r.mu.Lock()
	r.status = models.CommandStatusFailed
	r.mu.Unlock()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatal("agent failure ignored:", err)
	}
	r.mu.Lock()
	r.status = models.CommandStatusCompleted
	r.mu.Unlock()
	if err := e.awaitCommand(context.Background(), uuid.New(), time.Second); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.status = models.CommandStatusSent
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.awaitCommand(ctx, uuid.New(), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored:", err)
	}
}
