package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/shared/tzdetect"
)

func TestGetSystemTimeReportsPlatformZone(t *testing.T) {
	// Detected automatically (here: the explicit override path of the same
	// detector; host detection is covered in shared/tzdetect).
	env := map[string]string{"EDR_TIMEZONE": "Asia/Riyadh"}
	h := &Handlers{logger: logrus.New(), tz: &tzdetect.Detector{HostLocaltime: "missing-localtime",
		Getenv: func(k string) string { return env[k] }}}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/system/time", nil), rec)
	if err := h.GetSystemTime(c); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("%v %d", err, rec.Code)
	}
	var body struct {
		ServerTime string `json:"server_time"`
		Timezone   string `json:"timezone"`
		Source     string `json:"timezone_source"`
		Offset     int    `json:"utc_offset_seconds"`
		GeoIP      struct {
			Enabled bool `json:"enabled"`
		} `json:"geoip"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	st, err := time.Parse(time.RFC3339Nano, body.ServerTime)
	if err != nil || time.Since(st) > time.Minute || body.Timezone != "Asia/Riyadh" || body.Source != "EDR_TIMEZONE" || body.Offset != 3*3600 || body.GeoIP.Enabled {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}

	// Nothing configured and no host file: the process zone, never empty.
	h.tz = &tzdetect.Detector{HostLocaltime: "missing-localtime", Getenv: func(string) string { return "" }}
	if z := h.displayZone(); z.Location == nil || z.Source != "process" {
		t.Fatalf("fallback zone: %+v", z)
	}
}

func TestListAgentNetworkContextValidation(t *testing.T) {
	h := &Handlers{logger: logrus.New(), networkContextRepo: &repository.AgentNetworkContextRepository{}}
	for query, want := range map[string]int{
		"":               http.StatusBadRequest,
		"ids=not-a-uuid": http.StatusBadRequest,
		"ids=,,":         http.StatusBadRequest,
	} {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/agents/network-context?"+query, nil), rec)
		_ = h.ListAgentNetworkContext(c)
		if rec.Code != want {
			t.Errorf("%q → %d, want %d", query, rec.Code, want)
		}
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/agents/network-context?ids=x", nil), rec)
	_ = (&Handlers{logger: logrus.New()}).ListAgentNetworkContext(c)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no repository → %d", rec.Code)
	}
}
