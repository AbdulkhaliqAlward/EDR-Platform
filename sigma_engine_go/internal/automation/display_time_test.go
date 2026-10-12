package automation

import (
	"testing"
	"time"

	"github.com/edr-platform/shared/tzdetect"
)

func TestDisplayTimeUsesPlatformZone(t *testing.T) {
	at := time.Date(2026, 10, 12, 10, 4, 5, 0, time.UTC)
	t.Cleanup(func() { displayZone = tzdetect.Current })

	riyadh, _ := time.LoadLocation("Asia/Riyadh")
	displayZone = func() tzdetect.Zone { return tzdetect.Zone{Name: "Asia/Riyadh", Location: riyadh, Source: "host"} }
	if got := displayTime(at); got != "12 Oct 2026 13:04:05 +03 (Asia/Riyadh)" {
		t.Fatalf("Riyadh: %q", got)
	}

	// Unnamed host zone: the offset is shown instead of a name.
	fixed := time.FixedZone("", 5*3600+1800)
	displayZone = func() tzdetect.Zone { return tzdetect.Zone{Location: fixed, Source: "host"} }
	if got := displayTime(at); got != "12 Oct 2026 15:34:05 +0530 (UTC+05:30)" {
		t.Fatalf("offset-only: %q", got)
	}
}
