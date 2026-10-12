// Package tzdetect determines the platform display time zone automatically
// from the server host, so every service and dashboard shows times in the
// server's zone without manual configuration, and follows it when it changes.
//
// Resolution order:
//  1. EDR_TIMEZONE (explicit override, IANA name) when set and valid;
//  2. the host's /etc/localtime, bind-mounted read-only into the container
//     (EDR_HOST_LOCALTIME, default /host/etc/localtime) and identified as an
//     IANA zone by comparing its rules with the canonical zones;
//  3. TZ, then the process's own zone, else UTC.
//
// The result is re-evaluated at most once a minute. Note that Docker resolves
// the mounted /etc/localtime link when the container starts, so after
// "timedatectl set-timezone" the new zone is seen on the next container start
// (restart, deploy or reboot); mounting all of the host's /etc to see it
// immediately would expose host secrets and is deliberately not done.
package tzdetect

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Zone is the resolved display time zone.
type Zone struct {
	// Name is the IANA name ("Asia/Riyadh", "UTC"); "" when only the rules
	// are known (Location still converts correctly).
	Name     string
	Location *time.Location
	// Source says where it came from: "EDR_TIMEZONE", "host", "TZ", "process".
	Source string
}

// Detector resolves and caches the zone.
type Detector struct {
	HostLocaltime string // host /etc/localtime as mounted in the container
	ZoneTab       string // canonical zone list (zone1970.tab)
	TTL           time.Duration
	Getenv        func(string) string

	mu       sync.Mutex
	cached   Zone
	cachedAt time.Time
	hostSum  [32]byte
	hostName string
	hostLoc  *time.Location
}

// New returns a detector with the container defaults.
func New() *Detector {
	host := strings.TrimSpace(os.Getenv("EDR_HOST_LOCALTIME"))
	if host == "" {
		host = "/host/etc/localtime"
	}
	return &Detector{HostLocaltime: host, ZoneTab: "/usr/share/zoneinfo/zone1970.tab", TTL: time.Minute, Getenv: os.Getenv}
}

var (
	defaultOnce sync.Once
	defaultDet  *Detector
)

// Current returns the platform display zone (process-wide detector).
func Current() Zone {
	defaultOnce.Do(func() { defaultDet = New() })
	return defaultDet.Current()
}

// Current returns the zone, re-resolving it when the cache has expired.
func (d *Detector) Current() Zone {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cached.Location != nil && time.Since(d.cachedAt) < d.TTL {
		return d.cached
	}
	d.cached = d.resolve()
	d.cachedAt = time.Now()
	return d.cached
}

func (d *Detector) getenv(k string) string {
	if d.Getenv == nil {
		return os.Getenv(k)
	}
	return d.Getenv(k)
}

func (d *Detector) resolve() Zone {
	if tz := strings.TrimSpace(d.getenv("EDR_TIMEZONE")); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return Zone{Name: loc.String(), Location: loc, Source: "EDR_TIMEZONE"}
		}
	}
	if z, ok := d.fromHost(); ok {
		return z
	}
	if tz := strings.TrimPrefix(strings.TrimSpace(d.getenv("TZ")), ":"); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return Zone{Name: loc.String(), Location: loc, Source: "TZ"}
		}
	}
	if n := time.Local.String(); n != "" && n != "Local" {
		return Zone{Name: n, Location: time.Local, Source: "process"}
	}
	if _, off := time.Now().Zone(); off == 0 {
		return Zone{Name: "UTC", Location: time.UTC, Source: "process"}
	}
	return Zone{Location: time.Local, Source: "process"}
}

// fromHost identifies the host's /etc/localtime. The file content is hashed
// so the (cheap) comparison against the zone list only runs when it changes.
func (d *Detector) fromHost() (Zone, bool) {
	data, err := os.ReadFile(d.HostLocaltime)
	if err != nil || !bytes.HasPrefix(data, []byte("TZif")) {
		return Zone{}, false
	}
	sum := sha256.Sum256(data)
	if sum != d.hostSum || d.hostLoc == nil {
		loc, err := time.LoadLocationFromTZData("host", data)
		if err != nil {
			return Zone{}, false
		}
		d.hostSum, d.hostLoc, d.hostName = sum, loc, identify(loc, d.ZoneTab)
		if d.hostName != "" {
			if named, err := time.LoadLocation(d.hostName); err == nil {
				d.hostLoc = named
			}
		}
	}
	return Zone{Name: d.hostName, Location: d.hostLoc, Source: "host"}, true
}

var (
	// zone1970.tab lists the zones that differ since 1970.
	strictFrom = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	strictTo   = time.Date(2038, 1, 1, 0, 0, 0, 0, time.UTC)
)

// transitions lists the instants in [from, to) at which loc's zone period
// changes. ZoneBounds can stop where a zone file's explicit table ends and its
// POSIX rule takes over (end zero or not after t): the walk then steps past
// that point and continues, so rule-based transitions are included.
func transitions(loc *time.Location, from, to time.Time) []time.Time {
	var out []time.Time
	t := from
	for i := 0; i < 5000 && t.Before(to); i++ {
		_, end := t.In(loc).ZoneBounds()
		if end.IsZero() || !end.After(t) {
			t = t.Add(24 * time.Hour)
			continue
		}
		if !end.Before(to) {
			break
		}
		out = append(out, end)
		t = end
	}
	return out
}

// sampleRange returns instants twice a month in [from, to).
func sampleRange(from, to time.Time) []time.Time {
	var out []time.Time
	for t := from; t.Before(to); t = t.AddDate(0, 1, 0) {
		out = append(out, t, t.Add(14*24*time.Hour))
	}
	return out
}

// sameOffsets reports whether a and b have the same UTC offset throughout
// [from, to). Offsets are piecewise constant, so comparing them at every
// transition of either zone is exact; the twice-monthly samples additionally
// guard against a transition the walk could not see. Offsets only: zone
// abbreviations differ between tzdata releases.
func sameOffsets(a, b *time.Location, from, to time.Time) bool {
	check := func(t time.Time) bool {
		_, ao := t.In(a).Zone()
		_, bo := t.In(b).Zone()
		return ao == bo
	}
	for _, t := range sampleRange(from, to) {
		if !check(t) {
			return false
		}
	}
	for _, loc := range []*time.Location{a, b} {
		for _, t := range transitions(loc, from, to) {
			if !check(t) {
				return false
			}
		}
	}
	return true
}

// identify returns the IANA name whose rules match loc: UTC first, then the
// canonical zones over 1970–2037; failing that (different tzdata history on
// the host), a zone that is the only one matching the recent years. "" when
// it cannot be named — the rules themselves are still used for conversion.
func identify(loc *time.Location, zoneTab string) string {
	// A zone with offset 0 is only "UTC" when it calls itself so: e.g.
	// Africa/Abidjan has the same offset but is GMT.
	if abbr, _ := time.Now().In(loc).Zone(); abbr == "UTC" && sameOffsets(loc, time.UTC, strictFrom, strictTo) {
		return "UTC"
	}
	var cands, strict []*time.Location
	for _, name := range canonicalZones(zoneTab) {
		cand, err := time.LoadLocation(name)
		if err != nil {
			continue
		}
		cands = append(cands, cand)
		if sameOffsets(loc, cand, strictFrom, strictTo) {
			strict = append(strict, cand)
		}
	}
	if len(strict) > 0 {
		return pickByAbbreviation(loc, strict)
	}
	recentFrom, recentTo := time.Now().UTC().AddDate(-5, 0, 0), time.Now().UTC().AddDate(2, 0, 0)
	var recent []*time.Location
	for _, cand := range cands {
		if sameOffsets(loc, cand, recentFrom, recentTo) {
			recent = append(recent, cand)
		}
	}
	if len(recent) == 0 {
		return ""
	}
	if name := pickByAbbreviation(loc, recent); len(recent) == 1 || currentAbbrevMatch(loc, mustLoad(name)) {
		return name
	}
	return "" // ambiguous: keep the rules, no name
}

// pickByAbbreviation chooses among zones with identical offsets: zones such as
// Asia/Riyadh (+03) and Africa/Nairobi (EAT) differ only in their current
// abbreviation, which identifies the host's zone. Falls back to the first.
func pickByAbbreviation(loc *time.Location, zones []*time.Location) string {
	for _, z := range zones {
		if currentAbbrevMatch(loc, z) {
			return z.String()
		}
	}
	return zones[0].String()
}

// currentAbbrevMatch compares abbreviations over the coming year (summer and
// winter), where host and container tzdata agree.
func currentAbbrevMatch(a, b *time.Location) bool {
	if b == nil {
		return false
	}
	now := time.Now().UTC()
	for _, t := range []time.Time{now, now.AddDate(0, 3, 0), now.AddDate(0, 6, 0), now.AddDate(0, 9, 0)} {
		an, _ := t.In(a).Zone()
		bn, _ := t.In(b).Zone()
		if an != bn {
			return false
		}
	}
	return true
}

func mustLoad(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil
	}
	return loc
}

func canonicalZones(path string) []string {
	var names []string
	for _, p := range []string{path, filepath.Join(filepath.Dir(path), "zone.tab")} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			if cols := strings.Split(line, "\t"); len(cols) >= 3 {
				names = append(names, cols[2])
			}
		}
		f.Close()
		if len(names) > 0 {
			return names
		}
	}
	return names
}
