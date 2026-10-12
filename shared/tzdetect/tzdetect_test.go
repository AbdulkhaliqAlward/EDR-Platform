package tzdetect

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// tzif returns a real TZif file for name from Go's bundled zone database.
func tzif(t *testing.T, name string) []byte {
	t.Helper()
	z, err := zip.OpenReader(filepath.Join(runtime.GOROOT(), "lib", "time", "zoneinfo.zip"))
	if err != nil {
		t.Skip("Go zoneinfo.zip unavailable:", err)
	}
	defer z.Close()
	for _, f := range z.File {
		if f.Name == name {
			r, _ := f.Open()
			defer r.Close()
			b, _ := io.ReadAll(r)
			return b
		}
	}
	t.Fatalf("%s not in zoneinfo.zip", name)
	return nil
}

func detector(t *testing.T, env map[string]string) (*Detector, string) {
	dir := t.TempDir()
	tab := filepath.Join(dir, "zone1970.tab")
	// Real zone1970.tab format: codes, coordinates, TZ, comments.
	content := "# tzdb timezone descriptions\n" +
		"QA,BH\t+2517+05132\tAsia/Qatar\n" +
		"KE,DJ,ER,ET\t-0117+03649\tAfrica/Nairobi\n" +
		"SA,AQ,KW,YE\t+2438+04643\tAsia/Riyadh\n" +
		"SE\t+5920+01803\tEurope/Stockholm\n" +
		"US\t+404251-0740023\tAmerica/New_York\tEastern (most areas)\n"
	if err := os.WriteFile(tab, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "localtime")
	return &Detector{HostLocaltime: host, ZoneTab: tab, TTL: time.Hour, Getenv: func(k string) string { return env[k] }}, host
}

func TestHostZoneIsDetectedAndFollowsChanges(t *testing.T) {
	d, host := detector(t, map[string]string{})
	// Host set to Riyadh. Asia/Qatar is listed first with the same offset
	// today (+03) but differs in 1970–72; Africa/Nairobi has had the same
	// offset since 1970 and differs only in its abbreviation (EAT vs +03).
	// Neither may be chosen.
	if err := os.WriteFile(host, tzif(t, "Asia/Riyadh"), 0o644); err != nil {
		t.Fatal(err)
	}
	z := d.Current()
	if z.Name != "Asia/Riyadh" || z.Source != "host" {
		t.Fatalf("got %+v", z)
	}
	if got := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC).In(z.Location).Hour(); got != 13 {
		t.Fatalf("Riyadh conversion: %d", got)
	}

	// The administrator changes the server's zone: picked up after the TTL.
	if err := os.WriteFile(host, tzif(t, "Europe/Stockholm"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d.Current().Name != "Asia/Riyadh" {
		t.Fatal("cache ignored")
	}
	d.mu.Lock()
	d.cachedAt = time.Time{}
	d.mu.Unlock()
	z = d.Current()
	if z.Name != "Europe/Stockholm" {
		t.Fatalf("change not followed: %+v", z)
	}
	// DST handled by the real rules.
	if _, off := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).In(z.Location).Zone(); off != 2*3600 {
		t.Fatalf("Stockholm summer offset %d", off)
	}

	if err := os.WriteFile(host, tzif(t, "Etc/UTC"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.cachedAt = time.Time{}
	d.mu.Unlock()
	if z := d.Current(); z.Name != "UTC" {
		t.Fatalf("UTC host: %+v", z)
	}
}

func TestUnlistedHostZoneKeepsRulesWithoutName(t *testing.T) {
	d, host := detector(t, map[string]string{})
	// Asia/Kolkata (+05:30) is not in the test zone list: no name, but the
	// conversion must still be right.
	if err := os.WriteFile(host, tzif(t, "Asia/Kolkata"), 0o644); err != nil {
		t.Fatal(err)
	}
	z := d.Current()
	if z.Name != "" || z.Source != "host" {
		t.Fatalf("got %+v", z)
	}
	if _, off := time.Now().In(z.Location).Zone(); off != 5*3600+1800 {
		t.Fatalf("offset %d", off)
	}
}

func TestOverrideAndFallbacks(t *testing.T) {
	d, host := detector(t, map[string]string{"EDR_TIMEZONE": "America/New_York"})
	_ = os.WriteFile(host, tzif(t, "Asia/Riyadh"), 0o644)
	if z := d.Current(); z.Name != "America/New_York" || z.Source != "EDR_TIMEZONE" {
		t.Fatalf("override: %+v", z)
	}

	// No host file (mount missing) → TZ.
	d2, _ := detector(t, map[string]string{"TZ": "Europe/Stockholm"})
	if z := d2.Current(); z.Name != "Europe/Stockholm" || z.Source != "TZ" {
		t.Fatalf("TZ fallback: %+v", z)
	}
	// A directory or garbage at the mount point is ignored, not fatal.
	d3, host3 := detector(t, map[string]string{"EDR_TIMEZONE": "Not/AZone"})
	_ = os.WriteFile(host3, []byte("not a zone file"), 0o644)
	if z := d3.Current(); z.Location == nil || z.Source != "process" {
		t.Fatalf("garbage host file: %+v", z)
	}
}
