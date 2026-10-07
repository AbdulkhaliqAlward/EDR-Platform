package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

// upsertFake implements only UpsertWithDedup; other methods are unused.
type upsertFake struct {
	AlertRepository
	errs    []error // returned in order, then success
	calls   int
	mergeTo string // when set, simulate a dedup merge into this ID
	gotIDs  []string
}

func (f *upsertFake) UpsertWithDedup(_ context.Context, a *Alert, _ time.Duration) (*Alert, bool, error) {
	f.calls++
	f.gotIDs = append(f.gotIDs, a.ID)
	if f.calls <= len(f.errs) {
		return nil, false, f.errs[f.calls-1]
	}
	if f.mergeTo != "" {
		return &Alert{ID: f.mergeTo}, false, nil
	}
	return &Alert{ID: a.ID}, true, nil
}

func newTestWriter(repo AlertRepository) *AlertWriter {
	return NewAlertWriter(repo, AlertWriterConfig{DeduplicationWindow: time.Minute, BatchSize: 1, FlushInterval: time.Second})
}

func TestPersist_NewAlertKeepsItsID(t *testing.T) {
	repo := &upsertFake{}
	w := newTestWriter(repo)
	a := &domain.Alert{ID: "11111111-1111-4111-8111-111111111111", RuleID: "r"}

	id, isNew, err := w.Persist(context.Background(), a)
	require.NoError(t, err)
	assert.True(t, isNew)
	assert.Equal(t, "11111111-1111-4111-8111-111111111111", id)
	assert.Equal(t, id, a.ID)
	assert.Equal(t, a.ID, repo.gotIDs[0], "the generated ID is passed to the database as the primary key")
}

func TestPersist_DedupReturnsExistingID(t *testing.T) {
	repo := &upsertFake{mergeTo: "22222222-2222-4222-8222-222222222222"}
	w := newTestWriter(repo)
	a := &domain.Alert{ID: "11111111-1111-4111-8111-111111111111", RuleID: "r"}

	id, isNew, err := w.Persist(context.Background(), a)
	require.NoError(t, err)
	assert.False(t, isNew)
	assert.Equal(t, "22222222-2222-4222-8222-222222222222", a.ID, "downstream sinks must use the merged alert's ID")
	assert.Equal(t, a.ID, id)
}

func TestPersist_RetriesTransientErrors(t *testing.T) {
	repo := &upsertFake{errs: []error{errors.New("connection reset"), errors.New("timeout")}}
	w := newTestWriter(repo)
	_, _, err := w.Persist(context.Background(), &domain.Alert{ID: "11111111-1111-4111-8111-111111111111"})
	require.NoError(t, err)
	assert.Equal(t, 3, repo.calls)
}

func TestPersist_DataErrorsFailFast(t *testing.T) {
	repo := &upsertFake{errs: []error{&pgconn.PgError{Code: "22P02", Message: "invalid input"}}}
	w := newTestWriter(repo)
	_, _, err := w.Persist(context.Background(), &domain.Alert{ID: "11111111-1111-4111-8111-111111111111"})
	require.Error(t, err)
	assert.Equal(t, 1, repo.calls, "a data error cannot succeed on retry")
	assert.Equal(t, uint64(1), w.Metrics().AlertsDropped)
}

func TestPersist_GivesUpAfterMaxAttempts(t *testing.T) {
	errs := make([]error, persistMaxAttempts+2)
	for i := range errs {
		errs[i] = errors.New("db down")
	}
	repo := &upsertFake{errs: errs}
	w := newTestWriter(repo)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, err := w.Persist(ctx, &domain.Alert{ID: "11111111-1111-4111-8111-111111111111"})
	require.Error(t, err)
	assert.Equal(t, persistMaxAttempts, repo.calls)
}
