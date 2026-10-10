package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestReadinessReportsDependencyFailureAndRecovery(t *testing.T) {
	s := &Server{}
	e := echo.New()
	check := func(want int) string {
		t.Helper()
		r := httptest.NewRecorder()
		err := s.readyCheck(e.NewContext(httptest.NewRequest(http.MethodGet, "/readyz", nil), r))
		if err != nil || r.Code != want {
			t.Fatalf("code=%d err=%v body=%s", r.Code, err, r.Body.String())
		}
		return r.Body.String()
	}
	check(http.StatusServiceUnavailable)
	var dependencyErr error
	s.SetReadinessChecks(map[string]func(context.Context) error{"redis": func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded probe")
		}
		return dependencyErr
	}})
	check(http.StatusOK)
	dependencyErr = errors.New("private-connection-detail")
	if strings.Contains(check(http.StatusServiceUnavailable), dependencyErr.Error()) {
		t.Fatal("probe leaked error detail")
	}
	dependencyErr = nil
	check(http.StatusOK)
}
