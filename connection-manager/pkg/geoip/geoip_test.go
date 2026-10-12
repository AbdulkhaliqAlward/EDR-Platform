package geoip

import "testing"

func TestLookupScopesWithoutDatabase(t *testing.T) {
	var r *Resolver // no database: still classifies addresses
	cases := map[string]Location{
		"10.0.0.5:51234":         {IP: "10.0.0.5", Scope: ScopePrivate},
		"172.31.20.4:443":        {IP: "172.31.20.4", Scope: ScopePrivate},
		"192.168.1.20":           {IP: "192.168.1.20", Scope: ScopePrivate},
		"100.72.1.1:9":           {IP: "100.72.1.1", Scope: ScopePrivate}, // CGNAT
		"127.0.0.1:50051":        {IP: "127.0.0.1", Scope: ScopePrivate},
		"[::ffff:10.1.2.3]:5000": {IP: "10.1.2.3", Scope: ScopePrivate},
		"[fe80::1%eth0]:443":     {IP: "fe80::1", Scope: ScopePrivate},
		"203.0.113.9:50000":      {IP: "203.0.113.9", Scope: ScopeUnknown},
		"[2001:db8::7]:1":        {IP: "2001:db8::7", Scope: ScopeUnknown},
		"not-an-ip":              {IP: "not-an-ip", Scope: ScopeUnknown},
	}
	for in, want := range cases {
		if got := r.Lookup(in); got != want {
			t.Errorf("Lookup(%q) = %+v, want %+v", in, got, want)
		}
	}
	if r.Enabled() || r.Source() != "" || r.AttributionURL() != "" || r.Close() != nil {
		t.Fatal("nil resolver must be inert")
	}
}

func TestOpenMissingDatabase(t *testing.T) {
	if _, err := Open("does-not-exist.mmdb"); err == nil {
		t.Fatal("expected an error for a missing database")
	}
}
