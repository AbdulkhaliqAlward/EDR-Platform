package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type cacheCertificateRepo struct {
	CertificateRepository
	load func() ([]string, error)
	seen func(string) error
}

func (r *cacheCertificateRepo) GetCRLFingerprints(context.Context) ([]string, error) { return r.load() }
func (r *cacheCertificateRepo) UpdateLastSeen(_ context.Context, fp string) error    { return r.seen(fp) }

func TestCRLRefreshPreservesConcurrentRevocation(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	r := &cacheCertificateRepo{load: func() ([]string, error) { close(started); <-resume; return []string{"database"}, nil }}
	c := &CRLCache{certRepo: r, logger: logrus.New()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.refresh(); err != nil {
			t.Error(err)
		}
	}()
	<-started
	c.AddRevoked("new-revocation")
	close(resume)
	wg.Wait()
	if !c.IsRevoked("database") || !c.IsRevoked("new-revocation") {
		t.Fatal("refresh lost a revocation")
	}
	// Readers and immediate additions may overlap refresh publication.
	r.load = func() ([]string, error) { return []string{"database"}, nil }
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c.AddRevoked("new-revocation")
				c.IsRevoked("database")
				_ = c.refresh()
			}
		}()
	}
	wg.Wait()
}

func TestLastSeenRetainsFailuresAndNewObservations(t *testing.T) {
	c := &CRLCache{logger: logrus.New()}
	r := &cacheCertificateRepo{}
	c.certRepo = r
	c.lastSeenBuf.Store("short", time.Unix(1, 0))
	r.seen = func(string) error { return errors.New("DB unavailable") }
	c.flushLastSeen() // short fingerprint must not panic while logging
	if _, ok := c.lastSeenBuf.Load("short"); !ok {
		t.Fatal("failed flush lost retry")
	}
	r.seen = func(fp string) error { c.lastSeenBuf.Store(fp, time.Unix(2, 0)); return nil }
	c.flushLastSeen()
	if v, ok := c.lastSeenBuf.Load("short"); !ok || v != time.Unix(2, 0) {
		t.Fatal("in-flight observation was deleted")
	}
	r.seen = func(string) error { return nil }
	c.flushLastSeen()
	if _, ok := c.lastSeenBuf.Load("short"); ok {
		t.Fatal("successful observation was not drained")
	}
}
