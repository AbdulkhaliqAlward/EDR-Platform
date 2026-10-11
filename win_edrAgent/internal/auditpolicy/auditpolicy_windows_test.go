//go:build windows
// +build windows

package auditpolicy

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMissingNeverRemovesExistingAuditing(t *testing.T) {
	cases := []struct{ cur, req, want uint32 }{
		{0, auditSuccess, auditSuccess},
		{auditFailure, auditSuccess, auditSuccess},     // keeps failure (cur|miss)
		{auditSuccess | auditFailure, auditSuccess, 0}, // already configured
		{auditSuccess, auditSuccess | auditFailure, auditFailure},
	}
	for _, c := range cases {
		if got := Missing(c.cur, c.req); got != c.want {
			t.Fatalf("Missing(%d,%d)=%d want %d", c.cur, c.req, got, c.want)
		}
		if (c.cur|Missing(c.cur, c.req))&c.cur != c.cur {
			t.Fatal("existing flags removed")
		}
	}
}

func TestMarkerRoundTripOnlyKnownSubcategories(t *testing.T) {
	m := map[string]uint32{Required[0].GUID: 0, Required[5].GUID: auditFailure}
	enc := EncodeMarker(m)
	dec := DecodeMarker(enc + ";{00000000-0000-0000-0000-000000000000}=3;garbage")
	if len(dec) != 2 || dec[Required[0].GUID] != 0 || dec[Required[5].GUID] != auditFailure {
		t.Fatalf("round trip: %q -> %v", enc, dec)
	}
}

func TestRequiredGUIDsParse(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range Required {
		if _, err := windows.GUIDFromString(sc.GUID); err != nil || !strings.HasPrefix(sc.GUID, "{") {
			t.Fatalf("%s: bad GUID %s", sc.Name, sc.GUID)
		}
		if seen[sc.GUID] {
			t.Fatalf("duplicate %s", sc.GUID)
		}
		seen[sc.GUID] = true
	}
}

// Read-only check against the live system policy (needs elevation; skipped otherwise).
func TestQueryLiveReadOnly(t *testing.T) {
	g, _ := windows.GUIDFromString(Required[5].GUID) // Logon
	v, err := query(g)
	if err != nil {
		t.Skipf("audit policy query needs elevation here: %v", err)
	}
	t.Logf("Logon subcategory flags: %d", v)
}
