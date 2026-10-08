package detection

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
)

// ExceptionCondition is one field test of a detection exception. Field is a
// Sigma field name (Image, ParentImage, CommandLine, ...) resolved exactly as
// rule fields are; Op is equals | startswith | endswith | contains, always
// case-insensitive.
type ExceptionCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// DetectionException suppresses matches of a rule (or of every rule when
// RuleID is empty) on events satisfying ALL conditions, optionally only on
// one endpoint.
type DetectionException struct {
	ID         string
	RuleID     string
	AgentID    string
	Conditions []ExceptionCondition
	ExpiresAt  *time.Time
}

// ExceptionSource loads exceptions and stores hit counters.
type ExceptionSource interface {
	LoadExceptions(ctx context.Context) ([]DetectionException, error)
	RecordExceptionHits(ctx context.Context, hits map[string]int64) error
}

// ExceptionBatchSource supports safe retries after an uncertain commit.
type ExceptionBatchSource interface {
	RecordExceptionHitBatch(context.Context, string, map[string]int64) error
}

type compiledCondition struct {
	field string
	op    string
	value string // lower-cased
}

type compiledException struct {
	id        string
	agentID   string
	conds     []compiledCondition
	expiresAt *time.Time
}

// ExceptionManager holds the active exceptions and counts their hits.
type ExceptionManager struct {
	src      ExceptionSource
	interval time.Duration

	mu     sync.RWMutex
	byRule map[string][]*compiledException
	global []*compiledException

	startOnce  sync.Once
	cancel     context.CancelFunc
	done       chan struct{}
	flushMu    sync.Mutex
	inflight   map[string]int64
	inflightID string
	hitsMu     sync.Mutex
	hits       map[string]int64
}

// NewExceptionManager creates a manager refreshing from src every interval.
func NewExceptionManager(src ExceptionSource, interval time.Duration) *ExceptionManager {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ExceptionManager{src: src, interval: interval, byRule: map[string][]*compiledException{}, hits: map[string]int64{}}
}

// normalizeAgentID strips the certificate prefix and lower-cases the UUID.
func normalizeAgentID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "agent-")
}

// Replace installs a new exception set (used by Refresh and tests).
func (m *ExceptionManager) Replace(list []DetectionException) {
	byRule := map[string][]*compiledException{}
	var global []*compiledException
	for _, ex := range list {
		ce := &compiledException{id: ex.ID, agentID: normalizeAgentID(ex.AgentID), expiresAt: ex.ExpiresAt}
		for _, c := range ex.Conditions {
			op := strings.ToLower(strings.TrimSpace(c.Op))
			switch op {
			case "equals", "startswith", "endswith", "contains":
			default:
				op = "" // unknown operator: the exception can never match
			}
			ce.conds = append(ce.conds, compiledCondition{field: strings.TrimSpace(c.Field), op: op, value: strings.ToLower(c.Value)})
		}
		if len(ce.conds) == 0 {
			continue // an exception without conditions would hide everything
		}
		if rid := strings.ToLower(strings.TrimSpace(ex.RuleID)); rid != "" {
			byRule[rid] = append(byRule[rid], ce)
		} else {
			global = append(global, ce)
		}
	}
	m.mu.Lock()
	m.byRule, m.global = byRule, global
	m.mu.Unlock()
}

// Refresh reloads exceptions from the source; on error the previous set is
// kept (fail-static, so a database hiccup never re-floods analysts nor
// silently drops suppressions).
func (m *ExceptionManager) Refresh(ctx context.Context) error {
	list, err := m.src.LoadExceptions(ctx)
	if err != nil {
		return err
	}
	m.Replace(list)
	return nil
}

// Start refreshes exceptions and flushes hit counters until ctx ends.
func (m *ExceptionManager) Start(ctx context.Context) { m.startOnce.Do(func() { m.start(ctx) }) }
func (m *ExceptionManager) start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	m.done = make(chan struct{})
	refresh, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := m.Refresh(refresh)
	cancel()
	if err != nil {
		logger.Warnf("Detection exceptions not loaded (will retry): %v", err)
	}
	go func() {
		defer close(m.done)
		t := time.NewTicker(m.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				m.flushHits(context.Background())
				return
			case <-t.C:
				refresh, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := m.Refresh(refresh)
				cancel()
				if err != nil && ctx.Err() == nil {
					logger.Warnf("Detection exceptions refresh failed (keeping previous set): %v", err)
				}
				m.flushHits(ctx)
			}
		}
	}()
}

func (m *ExceptionManager) Stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
}

func (m *ExceptionManager) flushHits(ctx context.Context) {
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	for pass := 0; pass < 2; pass++ {
		m.hitsMu.Lock()
		if len(m.inflight) == 0 {
			if len(m.hits) == 0 {
				m.hitsMu.Unlock()
				return
			}
			m.inflight = m.hits
			m.inflightID = uuid.NewString()
			m.hits = map[string]int64{}
		}
		batch, id := m.inflight, m.inflightID
		m.hitsMu.Unlock()
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var err error
		if source, ok := m.src.(ExceptionBatchSource); ok {
			err = source.RecordExceptionHitBatch(writeCtx, id, batch)
		} else {
			err = m.src.RecordExceptionHits(writeCtx, batch)
		}
		cancel()
		if err != nil {
			logger.Warnf("Could not record detection exception hits: %v", err)
			return
		}
		m.hitsMu.Lock()
		m.inflight = nil
		m.inflightID = ""
		m.hitsMu.Unlock()
	}
}

// suppresses reports whether an exception hides this rule match.
func (m *ExceptionManager) suppresses(rule *domain.SigmaRule, event *domain.LogEvent, ec *eventContext) bool {
	if m == nil || rule == nil {
		return false
	}
	m.mu.RLock()
	scoped := m.byRule[strings.ToLower(rule.ID)]
	global := m.global
	m.mu.RUnlock()
	if len(scoped) == 0 && len(global) == 0 {
		return false
	}
	agent := ""
	now := time.Now()
	for _, list := range [2][]*compiledException{scoped, global} {
		for _, ex := range list {
			if ex.expiresAt != nil && now.After(*ex.expiresAt) {
				continue
			}
			if ex.agentID != "" {
				if agent == "" {
					agent = normalizeAgentID(event.GetStringField("agent_id"))
				}
				if ex.agentID != agent {
					continue
				}
			}
			if ex.matches(ec) {
				m.hitsMu.Lock()
				m.hits[ex.id]++
				m.hitsMu.Unlock()
				return true
			}
		}
	}
	return false
}

func (ex *compiledException) matches(ec *eventContext) bool {
	for _, c := range ex.conds {
		if c.op == "" || c.field == "" {
			return false
		}
		rf := ec.resolve(c.field)
		if !rf.present {
			return false
		}
		hit := false
		for _, v := range rf.lower {
			switch c.op {
			case "equals":
				hit = v == c.value
			case "startswith":
				hit = strings.HasPrefix(v, c.value)
			case "endswith":
				hit = strings.HasSuffix(v, c.value)
			case "contains":
				hit = strings.Contains(v, c.value)
			}
			if hit {
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}
