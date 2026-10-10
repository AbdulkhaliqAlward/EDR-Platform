package command

import (
	"context"
	"errors"
	"testing"
)

func TestCancelledCollectionDoesNotStartPowerShell(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// CommandContext rejects a cancelled context before process creation.
	_, err := (&Handler{}).collectEventLogAsJSON(ctx, "System", "system", 900000, 200)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled response must not outlive its parent: %v", err)
	}
}

func TestCapForensicsMs(t *testing.T) {
	if capForensicsMs(30_000) != 60_000 {
		t.Fatalf("below minimum: got %d", capForensicsMs(30_000))
	}
	const maxMs = int64(90 * 24 * 60 * 60 * 1000)
	if capForensicsMs(maxMs+1) != maxMs {
		t.Fatalf("expected cap at 90d ms")
	}
	if capForensicsMs(86400000) != 86400000 {
		t.Fatalf("mid range")
	}
}

func TestTimeRangeToMs(t *testing.T) {
	if got := timeRangeToMs("24h"); got != 86400000 {
		t.Fatalf("24h: got %d", got)
	}
	if got := timeRangeToMs("48"); got != 48*3600000 {
		t.Fatalf("48 as hours: got %d", got)
	}
	if got := timeRangeToMs("last 24 hours"); got != 86400000 {
		t.Fatalf("phrase: got %d", got)
	}
}

func TestForensicsLookbackMs(t *testing.T) {
	if got := forensicsLookbackMs(map[string]string{"time_range_ms": "3600000"}); got != 3600000 {
		t.Fatalf("explicit ms: got %d", got)
	}
	if got := forensicsLookbackMs(map[string]string{"time_range": "6h"}); got != 6*3600000 {
		t.Fatalf("6h: got %d", got)
	}
}

func TestCanonicalEventLogChannel(t *testing.T) {
	if got := canonicalEventLogChannel("security"); got != "Security" {
		t.Fatalf("security: %q", got)
	}
	if got := canonicalEventLogChannel("Microsoft-Windows-Sysmon/Operational"); got != "Microsoft-Windows-Sysmon/Operational" {
		t.Fatalf("preserve path: %q", got)
	}
}
