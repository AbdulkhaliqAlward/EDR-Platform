package automation

import (
	"sync"
	"testing"
	"time"
)

func TestDisplayTimeUsesPlatformZone(t *testing.T) {
	at := time.Date(2026, 10, 12, 10, 4, 5, 0, time.UTC)

	t.Setenv("EDR_TIMEZONE", "Asia/Riyadh")
	displayZoneOnce = sync.Once{}
	if got := displayTime(at); got != "12 Oct 2026 13:04:05 +03 (Asia/Riyadh)" {
		t.Fatalf("Riyadh: %q", got)
	}

	t.Setenv("EDR_TIMEZONE", "Not/AZone")
	displayZoneOnce = sync.Once{}
	if got := displayTime(at); got != "12 Oct 2026 10:04:05 UTC (UTC)" {
		t.Fatalf("invalid zone must fall back to UTC: %q", got)
	}
	displayZoneOnce = sync.Once{}
}
