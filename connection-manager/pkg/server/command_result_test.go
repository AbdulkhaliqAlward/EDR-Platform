package server

import (
	"context"
	"errors"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/contextkeys"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"testing"
)

type resultRepo struct {
	repository.CommandRepository
	cmd      *models.Command
	writes   int
	writeErr error
	last     models.CommandStatus
}

func (r *resultRepo) GetByID(context.Context, uuid.UUID) (*models.Command, error) { return r.cmd, nil }
func (r *resultRepo) UpdateStatus(_ context.Context, _ uuid.UUID, s models.CommandStatus, _ map[string]any, _ string) error {
	r.writes++
	r.last = s
	return r.writeErr
}
func TestCommandResultsRequireAuthenticatedOwnershipAndKnownTerminalStatus(t *testing.T) {
	owner, other, id := uuid.New(), uuid.New(), uuid.New()
	cases := []struct {
		name, cert, payload, state string
		owner                      uuid.UUID
		dbErr                      error
		code                       codes.Code
		writes                     int
	}{
		{name: "missing certificate", payload: owner.String(), state: "SUCCESS", owner: owner, code: codes.Unauthenticated},
		{name: "payload spoof", cert: owner.String(), payload: other.String(), state: "SUCCESS", owner: owner, code: codes.PermissionDenied},
		{name: "other endpoint command", cert: other.String(), payload: other.String(), state: "SUCCESS", owner: owner, code: codes.PermissionDenied},
		{name: "unknown status", cert: owner.String(), payload: owner.String(), state: "ACKNOWLEDGED", owner: owner, code: codes.InvalidArgument},
		{name: "durable save failed", cert: owner.String(), payload: owner.String(), state: "SUCCESS", owner: owner, dbErr: errors.New("synthetic DB failure"), code: codes.Unavailable, writes: 1},
		{name: "authenticated success", cert: "agent-" + owner.String(), payload: owner.String(), state: "SUCCESS", owner: owner, code: codes.OK, writes: 1},
		{name: "cancel is terminal", cert: owner.String(), payload: owner.String(), state: "CANCELLED", owner: owner, code: codes.OK, writes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &resultRepo{cmd: &models.Command{ID: id, AgentID: tc.owner, CommandType: "synthetic_read"}, writeErr: tc.dbErr}
			log := logrus.New()
			log.SetOutput(io.Discard)
			s := &Server{commandRepo: repo, logger: log}
			ctx := context.WithValue(context.Background(), contextkeys.AgentIDKey, tc.cert)
			_, err := s.SendCommandResult(ctx, &edrv1.CommandResult{CommandId: id.String(), AgentId: tc.payload, Status: tc.state})
			if status.Code(err) != tc.code || repo.writes != tc.writes {
				t.Fatalf("code=%v writes=%d err=%v", status.Code(err), repo.writes, err)
			}
			if tc.state == "CANCELLED" && repo.last != models.CommandStatusCancelled {
				t.Fatal("cancelled result treated as success")
			}
		})
	}
}
