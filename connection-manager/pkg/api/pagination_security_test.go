package api

import (
	"github.com/edr-platform/connection-manager/pkg/audit"
	"github.com/labstack/echo/v4"
	"net/http/httptest"
	"testing"
)

func TestSecurityEventPageValidation(t *testing.T) {
	for _, query := range []string{"cursor=bad", "limit=0", "offset=25", "sort=severity", "actor_id=invalid", "severity=invalid", "from=invalid", "until=bad", "since=2026-01-01T00:00:00Z&from=2026-02-01T00:00:00Z", "from=2099-01-01T00:00:00Z"} {
		h := &Handlers{securityEventRepo: audit.NewRepository(nil)}
		w := httptest.NewRecorder()
		err := h.ListSecurityEvents(echo.New().NewContext(httptest.NewRequest("GET", "/security/events?"+query, nil), w))
		if err != nil || w.Code != 400 {
			t.Fatalf("%s: status=%d err=%v", query, w.Code, err)
		}
	}
}
