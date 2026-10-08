// Package repository provides the in-memory CRL cache backed by PostgreSQL.
package repository

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CRLCache provides an in-memory certificate revocation cache.
// IsRevoked() reads from cache only — never hits the database.
// The cache is refreshed from DB every 60 seconds via a background goroutine.
type CRLCache struct {
	certRepo CertificateRepository
	logger   *logrus.Logger

	// revoked maps fingerprint → true for revoked certificates.
	revokedMu sync.RWMutex
	revoked   map[string]bool

	// lastSeenBuf buffers fingerprint → latest seen time for batch DB writes.
	lastSeenBuf sync.Map

	cancel context.CancelFunc
}

// NewCRLCache creates a new CRL cache and starts the background refresh goroutine.
// Call Stop() on shutdown to clean up.
func NewCRLCache(certRepo CertificateRepository, logger *logrus.Logger) *CRLCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &CRLCache{
		certRepo: certRepo,
		logger:   logger,
		cancel:   cancel,
	}

	// Initial load (best-effort — don't block boot on DB failure)
	if err := c.refresh(); err != nil {
		logger.WithError(err).Warn("[CRL] Initial cache load failed — cache empty until next refresh")
	} else {
		logger.Info("[CRL] In-memory CRL cache initialized")
	}

	// Background refresh every 60 seconds
	go c.refreshLoop(ctx)

	// Background last_seen_at flush every 30 seconds
	go c.lastSeenFlushLoop(ctx)

	return c
}

// IsRevoked checks if a fingerprint is in the revocation cache.
// This NEVER queries the database — cache only.
func (c *CRLCache) IsRevoked(fingerprint string) bool {
	c.revokedMu.RLock()
	defer c.revokedMu.RUnlock()
	return c.revoked[fingerprint]
}

// AddRevoked immediately adds a fingerprint to the in-memory cache.
// Called when a certificate is revoked via the REST API so the change
// takes effect instantly without waiting for the next refresh cycle.
func (c *CRLCache) AddRevoked(fingerprint string) {
	c.revokedMu.Lock()
	defer c.revokedMu.Unlock()
	if c.revoked == nil {
		c.revoked = make(map[string]bool)
	}
	c.revoked[fingerprint] = true
}

// RecordLastSeen records that a fingerprint was seen at the current time.
// This is called asynchronously from the gRPC interceptor and never blocks.
func (c *CRLCache) RecordLastSeen(fingerprint string) {
	c.lastSeenBuf.Store(fingerprint, time.Now())
}

// Stop cancels the background goroutines.
func (c *CRLCache) Stop() {
	c.cancel()
}

// refresh reloads the CRL from the database.
func (c *CRLCache) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fingerprints, err := c.certRepo.GetCRLFingerprints(ctx)
	if err != nil {
		return err
	}

	// Build fresh revoked set
	newRevoked := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		newRevoked[fp] = true
	}

	// Merge: preserve any manually-added entries (via AddRevoked) not yet in DB.
	// This ensures immediate revocations are never evicted by the next refresh.
	// Merge and publish under the same lock used by AddRevoked. A revocation
	// arriving during the DB read cannot be lost between merge and publication.
	c.revokedMu.Lock()
	for fp := range c.revoked {
		newRevoked[fp] = true
	}
	c.revoked = newRevoked
	c.revokedMu.Unlock()

	c.logger.WithField("count", len(fingerprints)).Debug("[CRL] Cache refreshed from DB")
	return nil
}

// refreshLoop runs refresh every 60 seconds.
func (c *CRLCache) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.refresh(); err != nil {
				c.logger.WithError(err).Warn("[CRL] Cache refresh failed")
			}
		}
	}
}

// lastSeenFlushLoop flushes buffered last_seen_at updates to the DB every 30 seconds.
func (c *CRLCache) lastSeenFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushLastSeen()
		}
	}
}

// flushLastSeen writes all buffered last_seen_at entries to the DB and clears the buffer.
func (c *CRLCache) flushLastSeen() {
	var count int
	c.lastSeenBuf.Range(func(key, value any) bool {
		fingerprint := key.(string)

		dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.certRepo.UpdateLastSeen(dbCtx, fingerprint); err != nil {
			c.logger.WithError(err).WithField("fingerprint", fingerprint[:min(12, len(fingerprint))]).
				Warn("[CRL] Failed to flush last_seen_at")
		} else {
			// Keep observations made while this write was in flight, and keep
			// failed writes for retry on the next flush.
			c.lastSeenBuf.CompareAndDelete(key, value)
			count++
		}
		cancel()
		return true
	})
	if count > 0 {
		c.logger.WithField("count", count).Debug("[CRL] Flushed last_seen_at updates")
	}
}
