// Package geoip resolves an agent's connection address to a country and
// place using a local MaxMind-format database (DB-IP "IP to City Lite" or
// MaxMind GeoLite2/GeoIP2 City). Lookups are offline: agent addresses are
// never sent to a third-party service.
package geoip

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Scope classifies the address the server saw.
const (
	ScopePublic  = "public"  // routable Internet address: geolocated
	ScopePrivate = "private" // LAN / loopback / CGNAT / link-local: no geography
	ScopeUnknown = "unknown" // public, but not in the database (or no database)
)

// Location is the geography of one address.
type Location struct {
	IP          string `json:"ip"`
	Scope       string `json:"scope"`
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
}

// Resolver looks addresses up in an opened database. A nil *Resolver is
// valid and classifies addresses without geography.
type Resolver struct {
	mu     sync.RWMutex
	db     *maxminddb.Reader
	dbType string
}

// Open loads a .mmdb file.
func Open(path string) (*Resolver, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip database %q: %w", path, err)
	}
	return &Resolver{db: db, dbType: db.Metadata.DatabaseType}, nil
}

// Close releases the database.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db == nil {
		return nil
	}
	err := r.db.Close()
	r.db = nil
	return err
}

// Enabled reports whether a database is loaded.
func (r *Resolver) Enabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db != nil
}

// Source names the database (and its required attribution).
func (r *Resolver) Source() string {
	if !r.Enabled() {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(r.dbType), "dbip") {
		return "DB-IP (IP to City Lite, CC BY 4.0)"
	}
	return r.dbType
}

// AttributionURL is the link required by the database licence, if any.
func (r *Resolver) AttributionURL() string {
	if r.Enabled() && strings.HasPrefix(strings.ToLower(r.dbType), "dbip") {
		return "https://db-ip.com"
	}
	return ""
}

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// IsPrivate reports addresses that have no public geography.
func IsPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || cgnat.Contains(ip)
}

type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// Lookup resolves an address (IPv4 or IPv6, with or without a port).
func (r *Resolver) Lookup(addr string) Location {
	host := strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if i := strings.IndexByte(host, '%'); i >= 0 { // IPv6 zone
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return Location{IP: host, Scope: ScopeUnknown}
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // IPv4-mapped IPv6 (::ffff:a.b.c.d) → a.b.c.d
	}
	loc := Location{IP: ip.String(), Scope: ScopeUnknown}
	if IsPrivate(ip) {
		loc.Scope = ScopePrivate
		return loc
	}
	if r == nil {
		return loc
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.db == nil {
		return loc
	}
	var rec record
	if err := r.db.Lookup(ip, &rec); err != nil || rec.Country.ISOCode == "" {
		return loc
	}
	loc.Scope = ScopePublic
	loc.CountryCode = strings.ToUpper(rec.Country.ISOCode)
	loc.Country = rec.Country.Names["en"]
	if len(rec.Subdivisions) > 0 {
		loc.Region = rec.Subdivisions[0].Names["en"]
	}
	loc.City = rec.City.Names["en"]
	return loc
}
