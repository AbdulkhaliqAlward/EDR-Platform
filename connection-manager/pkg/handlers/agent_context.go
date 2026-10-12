package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/agentclock"
	"github.com/edr-platform/connection-manager/pkg/geoip"
)

const (
	contextRewriteEvery   = 5 * time.Minute
	contextOffsetChange   = 500 * time.Millisecond
	contextWriteTimeout   = 5 * time.Second
	contextLoadTimeout    = 2 * time.Second
	contextMaxConcurrency = 8
)

// AgentContextRecorder measures each agent's clock offset and geolocates the
// address it connects from, from heartbeats. It feeds the clock tracker used
// to normalise event times and persists both for the dashboard. All of it is
// best-effort: it never delays or fails a heartbeat.
type AgentContextRecorder struct {
	logger *logrus.Logger
	geo    *geoip.Resolver
	repo   *repository.AgentNetworkContextRepository
	clock  *agentclock.Tracker

	mu   sync.Mutex
	last map[string]recordedContext
	sem  chan struct{}
}

type recordedContext struct {
	addr   string
	loc    geoip.Location
	offset time.Duration
	at     time.Time
}

// NewAgentContextRecorder creates the recorder. geo and repo may be nil.
func NewAgentContextRecorder(logger *logrus.Logger, geo *geoip.Resolver, repo *repository.AgentNetworkContextRepository) *AgentContextRecorder {
	r := &AgentContextRecorder{logger: logger, geo: geo, repo: repo, last: map[string]recordedContext{}, sem: make(chan struct{}, contextMaxConcurrency)}
	var load agentclock.Loader
	if repo != nil {
		load = func(agentID string) (time.Duration, time.Time, bool) {
			id, err := uuid.Parse(agentID)
			if err != nil {
				return 0, time.Time{}, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), contextLoadTimeout)
			defer cancel()
			c, err := repo.Get(ctx, id)
			if err != nil || c == nil || c.ClockOffsetMs == nil || c.ClockMeasuredAt == nil {
				return 0, time.Time{}, false
			}
			return time.Duration(*c.ClockOffsetMs) * time.Millisecond, *c.ClockMeasuredAt, true
		}
	}
	r.clock = agentclock.New(load)
	return r
}

// Clock is the tracker event ingestion uses to normalise timestamps.
func (r *AgentContextRecorder) Clock() *agentclock.Tracker {
	if r == nil {
		return nil
	}
	return r.clock
}

// Observe records one heartbeat: agentTime is the agent's send time,
// peerAddr the connection address the server saw.
func (r *AgentContextRecorder) Observe(agentID, peerAddr string, agentTime time.Time) {
	if r == nil || agentID == "" {
		return
	}
	now := time.Now()
	offset := r.clock.Observe(agentID, agentTime, now)

	r.mu.Lock()
	prev, seen := r.last[agentID]
	loc := prev.loc
	if !seen || prev.addr != peerAddr {
		loc = r.geo.Lookup(peerAddr) // offline database: microseconds
	}
	diff := offset - prev.offset
	if diff < 0 {
		diff = -diff
	}
	due := !seen || prev.addr != peerAddr || diff >= contextOffsetChange || now.Sub(prev.at) >= contextRewriteEvery
	if due {
		r.last[agentID] = recordedContext{addr: peerAddr, loc: loc, offset: offset, at: now}
	}
	r.mu.Unlock()
	if !due || r.repo == nil {
		return
	}

	id, err := uuid.Parse(agentID)
	if err != nil {
		return
	}
	row := &repository.AgentNetworkContext{
		AgentID: id, PublicIP: loc.IP, NetworkScope: loc.Scope,
		CountryCode: loc.CountryCode, Country: loc.Country, Region: loc.Region, City: loc.City,
		GeoSource: r.geo.Source(),
	}
	if peerAddr == "" {
		row.NetworkScope = geoip.ScopeUnknown
	}
	row.GeoResolvedAt = &now
	if !agentTime.IsZero() {
		ms := offset.Milliseconds()
		row.ClockOffsetMs, row.ClockMeasuredAt = &ms, &now
	}
	select {
	case r.sem <- struct{}{}:
	default:
		// Writers saturated: retry on a later heartbeat instead of piling up.
		r.mu.Lock()
		delete(r.last, agentID)
		r.mu.Unlock()
		return
	}
	go func() {
		defer func() { <-r.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), contextWriteTimeout)
		defer cancel()
		if err := r.repo.Upsert(ctx, row); err != nil {
			r.logger.WithError(err).WithField("agent_id", agentID).Warn("Failed to persist agent network context")
			r.mu.Lock()
			delete(r.last, agentID) // write again on the next heartbeat
			r.mu.Unlock()
		}
	}()
}
