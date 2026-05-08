// Package audit provides a non-blocking, batching security event logger.
// All public methods are nil-safe — callers may call them even when the
// logger pointer is nil (e.g., DB unavailable at startup).
package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
)

// ──────────────────────────────────────────────────────────────────────────────
// Event types and severity levels
// ──────────────────────────────────────────────────────────────────────────────

const (
	// Event types
	EventLoginSuccess            = "login_success"
	EventLoginFailed             = "login_failed"
	EventLoginLocked             = "login_locked"
	EventLogout                  = "logout"
	EventTokenRefreshed          = "token_refreshed"
	EventTokenReuseDetected      = "token_reuse_detected"
	EventSessionSuperseded       = "session_superseded"
	EventCertRevoked             = "cert_revoked"
	EventCertRenewed             = "cert_renewed"
	EventAgentEnrolled           = "agent_enrolled"
	EventCertRevocationAttempted = "cert_revocation_attempted"
	EventCertRejectedCRL         = "cert_rejected_crl"

	// Severity levels
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// ──────────────────────────────────────────────────────────────────────────────
// Event model
// ──────────────────────────────────────────────────────────────────────────────

// Event represents a single security audit event.
type Event struct {
	ID          uuid.UUID         `json:"id"`
	EventType   string            `json:"event_type"`
	Severity    string            `json:"severity"`
	ActorID     *uuid.UUID        `json:"actor_id,omitempty"`
	ActorName   string            `json:"actor_name"`
	TargetID    *uuid.UUID        `json:"target_id,omitempty"`
	TargetType  string            `json:"target_type"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Logger
// ──────────────────────────────────────────────────────────────────────────────

const (
	defaultBatchSize    = 50
	defaultFlushEvery   = 5 * time.Second
	defaultChannelDepth = 2048
)

// Logger is a non-blocking, batching audit event logger backed by PostgreSQL.
type Logger struct {
	pool   *pgxpool.Pool
	logger *logrus.Logger
	ch     chan *Event
	wg     sync.WaitGroup
	once   sync.Once
	cancel context.CancelFunc
}

// New creates a new audit Logger. Call Shutdown() during graceful shutdown.
// Returns nil if pool is nil (all Log* calls become no-ops on nil *Logger).
func New(pool *pgxpool.Pool, logger *logrus.Logger) *Logger {
	if pool == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Logger{
		pool:   pool,
		logger: logger,
		ch:     make(chan *Event, defaultChannelDepth),
		cancel: cancel,
	}
	l.wg.Add(1)
	go l.worker(ctx)
	return l
}

// Shutdown flushes remaining events and stops the background worker.
func (l *Logger) Shutdown(ctx context.Context) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.cancel()
		// Drain the channel with a deadline.
		done := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			l.logger.Warn("[Audit] Shutdown timed out — some events may be lost")
		}
	})
}

// log enqueues an event. Never blocks the caller — drops with a warning if channel is full.
func (l *Logger) log(evt *Event) {
	if l == nil || evt == nil {
		return
	}
	evt.ID = uuid.New()
	evt.CreatedAt = time.Now().UTC()
	if evt.Metadata == nil {
		evt.Metadata = map[string]string{}
	}
	select {
	case l.ch <- evt:
	default:
		l.logger.Warn("[Audit] Channel full — security event dropped")
	}
}

// worker batches and persists events to PostgreSQL.
func (l *Logger) worker(ctx context.Context) {
	defer l.wg.Done()
	ticker := time.NewTicker(defaultFlushEvery)
	defer ticker.Stop()
	batch := make([]*Event, 0, defaultBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := l.persist(batch); err != nil {
			// One retry with a brief pause.
			time.Sleep(500 * time.Millisecond)
			if err2 := l.persist(batch); err2 != nil {
				l.logger.WithError(err2).Warn("[Audit] Failed to persist batch after retry")
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case evt := <-l.ch:
			batch = append(batch, evt)
			if len(batch) >= defaultBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			// Drain remaining events.
			draining := true
			for draining {
				select {
				case evt := <-l.ch:
					batch = append(batch, evt)
				default:
					draining = false
				}
			}
			flush()
			return
		}
	}
}

// persist writes a batch to the database using a single multi-row INSERT.
func (l *Logger) persist(batch []*Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	for _, evt := range batch {
		meta, _ := json.Marshal(evt.Metadata)
		_, err := conn.Exec(ctx, `
			INSERT INTO security_events
			    (id, event_type, severity, actor_id, actor_name, target_id, target_type,
			     ip_address, user_agent, description, metadata, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (id) DO NOTHING`,
			evt.ID, evt.EventType, evt.Severity,
			nullableUUID(evt.ActorID), evt.ActorName,
			nullableUUID(evt.TargetID), evt.TargetType,
			evt.IPAddress, evt.UserAgent, evt.Description,
			string(meta), evt.CreatedAt,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func nullableUUID(u *uuid.UUID) interface{} {
	if u == nil {
		return nil
	}
	return u.String()
}

// ──────────────────────────────────────────────────────────────────────────────
// Typed constructors — one per event type for clean call sites
// ──────────────────────────────────────────────────────────────────────────────

// LoginSuccess logs a successful user login.
func (l *Logger) LoginSuccess(actorID uuid.UUID, actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventLoginSuccess,
		Severity:    SeverityInfo,
		ActorID:     &actorID,
		ActorName:   actorName,
		TargetType:  "user",
		TargetID:    &actorID,
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "User logged in successfully",
	})
}

// LoginFailed logs a failed login attempt.
func (l *Logger) LoginFailed(actorName, ip, ua, reason string) {
	l.log(&Event{
		EventType:   EventLoginFailed,
		Severity:    SeverityWarning,
		ActorName:   actorName,
		TargetType:  "user",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "Login failed: " + reason,
		Metadata:    map[string]string{"reason": reason},
	})
}

// LoginLocked logs an account lockout.
func (l *Logger) LoginLocked(actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventLoginLocked,
		Severity:    SeverityCritical,
		ActorName:   actorName,
		TargetType:  "user",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "Account locked after too many failed login attempts",
	})
}

// Logout logs a user logout.
func (l *Logger) Logout(actorID uuid.UUID, actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventLogout,
		Severity:    SeverityInfo,
		ActorID:     &actorID,
		ActorName:   actorName,
		TargetID:    &actorID,
		TargetType:  "user",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "User logged out",
	})
}

// TokenRefreshed logs a successful refresh token rotation.
func (l *Logger) TokenRefreshed(actorID uuid.UUID, actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventTokenRefreshed,
		Severity:    SeverityInfo,
		ActorID:     &actorID,
		ActorName:   actorName,
		TargetID:    &actorID,
		TargetType:  "session",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "Refresh token rotated",
	})
}

// TokenReuseDetected logs a refresh token reuse attack detection.
func (l *Logger) TokenReuseDetected(actorID *uuid.UUID, actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventTokenReuseDetected,
		Severity:    SeverityCritical,
		ActorID:     actorID,
		ActorName:   actorName,
		TargetType:  "session",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "Refresh token reuse detected — all sessions revoked",
	})
}

// SessionSuperseded logs single-session enforcement displacing an older session.
func (l *Logger) SessionSuperseded(actorID uuid.UUID, actorName, ip, ua string) {
	l.log(&Event{
		EventType:   EventSessionSuperseded,
		Severity:    SeverityWarning,
		ActorID:     &actorID,
		ActorName:   actorName,
		TargetID:    &actorID,
		TargetType:  "session",
		IPAddress:   ip,
		UserAgent:   ua,
		Description: "Previous session superseded by new login",
	})
}

// CertRevoked logs a manual certificate revocation.
func (l *Logger) CertRevoked(actorID uuid.UUID, actorName string, certID uuid.UUID, agentID, reason string) {
	l.log(&Event{
		EventType:   EventCertRevoked,
		Severity:    SeverityWarning,
		ActorID:     &actorID,
		ActorName:   actorName,
		TargetID:    &certID,
		TargetType:  "certificate",
		Description: "Certificate manually revoked: " + reason,
		Metadata:    map[string]string{"agent_id": agentID, "reason": reason},
	})
}

// CertRenewed logs an auto-renewed certificate.
func (l *Logger) CertRenewed(agentID string, oldCertID, newCertID uuid.UUID) {
	l.log(&Event{
		EventType:   EventCertRenewed,
		Severity:    SeverityInfo,
		ActorName:   "system",
		TargetID:    &newCertID,
		TargetType:  "certificate",
		Description: "Certificate auto-renewed",
		Metadata:    map[string]string{"agent_id": agentID, "old_cert_id": oldCertID.String()},
	})
}

// AgentEnrolled logs a new agent enrollment.
func (l *Logger) AgentEnrolled(agentID uuid.UUID, certID uuid.UUID, fingerprint string) {
	l.log(&Event{
		EventType:   EventAgentEnrolled,
		Severity:    SeverityInfo,
		ActorName:   "system",
		TargetID:    &agentID,
		TargetType:  "agent",
		Description: "Agent enrolled and certificate issued",
		Metadata:    map[string]string{"cert_id": certID.String(), "fingerprint": fingerprint},
	})
}

// CertRejectedCRL logs a gRPC connection rejected by the CRL check.
func (l *Logger) CertRejectedCRL(fingerprint, agentID, remoteAddr string) {
	l.log(&Event{
		EventType:   EventCertRejectedCRL,
		Severity:    SeverityCritical,
		ActorName:   agentID,
		TargetType:  "certificate",
		IPAddress:   remoteAddr,
		Description: "gRPC connection rejected: certificate on CRL",
		Metadata:    map[string]string{"fingerprint": fingerprint},
	})
}
