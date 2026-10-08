package response

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

var ErrEndpointBusy = errors.New("the endpoint is executing another command or playbook")

type endpointSlot struct {
	token chan struct{}
	refs  int // holder plus waiters; removes idle endpoint entries safely
}

func (e *Engine) endpointSlot(agentID string) (*endpointSlot, func()) {
	agentID = NormalizeAgentID(agentID)
	e.agentLocksMu.Lock()
	s := e.agentLocks[agentID]
	if s == nil {
		s = &endpointSlot{token: make(chan struct{}, 1)}
		e.agentLocks[agentID] = s
	}
	s.refs++
	e.agentLocksMu.Unlock()
	return s, func() {
		e.agentLocksMu.Lock()
		s.refs--
		if s.refs == 0 {
			delete(e.agentLocks, agentID)
		}
		e.agentLocksMu.Unlock()
	}
}

// AcquireEndpoint serializes a whole operation, including its result wait.
// Legacy triage and the response engine share this gate. It is process-local.
func (e *Engine) AcquireEndpoint(ctx context.Context, agentID string) (func(), error) {
	s, drop := e.endpointSlot(agentID)
	select {
	case s.token <- struct{}{}:
		if ctx.Err() != nil || e.baseCtx.Err() != nil {
			<-s.token
			drop()
			return nil, context.Canceled
		}
		var once sync.Once
		return func() { once.Do(func() { <-s.token; drop() }) }, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	case <-e.baseCtx.Done():
		drop()
		return nil, e.baseCtx.Err()
	}
}

// TryAcquireEndpoint refuses a raw HTTP command while a run owns the host,
// before persisting or dispatching that command.
func (e *Engine) TryAcquireEndpoint(agentID string) (func(), error) {
	if e.baseCtx.Err() != nil {
		return nil, e.baseCtx.Err()
	}
	s, drop := e.endpointSlot(agentID)
	select {
	case s.token <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.token; drop() }) }, nil
	default:
		drop()
		return nil, ErrEndpointBusy
	}
}

func (e *Engine) admitWork() bool {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	if e.stopping {
		return false
	}
	e.wg.Add(1)
	return true
}

// HoldForCommand transfers a raw command's endpoint gate to a background
// result waiter; HTTP completion must not release a still-running command.
func (e *Engine) HoldForCommand(id uuid.UUID, timeout int, release func()) {
	if !e.admitWork() {
		release()
		return
	}
	go func() {
		defer e.wg.Done()
		defer release()
		s := &BoundStep{Timeout: timeout}
		if err := e.awaitResult(e.baseCtx, id, s); err != nil {
			e.logger.WithError(err).WithField("command_id", id).Debug("[Response] Raw command result wait ended")
		}
	}()
}
