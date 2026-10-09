package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func cond(field, op, value string) repository.ExceptionCondition {
	return repository.ExceptionCondition{Field: field, Op: op, Value: value}
}

type exceptionEndpointService struct {
	service.AgentService
	agent *models.Agent
	err   error
}

func (s *exceptionEndpointService) GetByID(context.Context, uuid.UUID) (*models.Agent, error) {
	return s.agent, s.err
}

// Rejected scopes must return before any exception is persisted. The deliberately
// empty repository would panic if these cases reached the database write.
func TestCreateExceptionRejectsUnverifiedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		agent  string
		svc    service.AgentService
		status int
	}{
		{"invalid identifier", "not-a-uuid", nil, http.StatusBadRequest},
		{"missing lookup service", uuid.NewString(), nil, http.StatusServiceUnavailable},
		{"deleted endpoint", uuid.NewString(), &exceptionEndpointService{err: repository.ErrNotFound}, http.StatusBadRequest},
		{"missing endpoint row", uuid.NewString(), &exceptionEndpointService{}, http.StatusBadRequest},
		{"lookup failure", uuid.NewString(), &exceptionEndpointService{err: errors.New("database unavailable")}, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{agentSvc: tc.svc, detectionExceptionRepo: &repository.DetectionExceptionRepository{}, logger: logrus.New()}
			body := `{"name":"Backup","reason":"Approved","rule_id":"rule","agent_id":"` + tc.agent + `","conditions":[{"field":"Image","op":"equals","value":"backup.exe"}]}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/detection-exceptions", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			c.Set(string(ContextKeyUser), &UserClaims{Username: "admin", Roles: []string{"admin"}})
			if err := h.CreateDetectionException(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestValidateExceptionConditions(t *testing.T) {
	img := `C:\Program Files\Backup\agent.exe`
	cases := []struct {
		name   string
		conds  []repository.ExceptionCondition
		global bool
		ok     bool
	}{
		{"rule-scoped command-line contains", []repository.ExceptionCondition{cond("CommandLine", "contains", "--nightly")}, false, true},
		{"no conditions", nil, false, false},
		{"unknown field", []repository.ExceptionCondition{cond("Foo", "equals", "x")}, false, false},
		{"regex operator", []repository.ExceptionCondition{cond("Image", "regex", ".*")}, false, false},
		{"wildcard value", []repository.ExceptionCondition{cond("Image", "equals", `C:\*`)}, false, false},
		{"too-short partial", []repository.ExceptionCondition{cond("CommandLine", "contains", "-c")}, false, false},
		{"global without anchor", []repository.ExceptionCondition{cond("CommandLine", "contains", "--nightly")}, true, false},
		{"global with exact image", []repository.ExceptionCondition{cond("Image", "equals", img), cond("CommandLine", "contains", "--nightly")}, true, true},
		{"global with endswith image is not an anchor", []repository.ExceptionCondition{cond("Image", "endswith", `\agent.exe`)}, true, false},
		{"control characters", []repository.ExceptionCondition{cond("Image", "equals", "a\x00b")}, false, false},
	}
	for _, tc := range cases {
		_, err := validateExceptionConditions(tc.conds, tc.global)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v err=%v", tc.name, tc.ok, err)
		}
	}
	out, err := validateExceptionConditions([]repository.ExceptionCondition{cond(" Image ", " EQUALS ", "  "+img+" ")}, true)
	if err != nil || out[0].Field != "Image" || out[0].Op != "equals" || out[0].Value != img {
		t.Fatalf("conditions must be normalised: %+v %v", out, err)
	}
}
