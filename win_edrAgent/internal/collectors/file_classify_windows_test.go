//go:build windows
// +build windows

package collectors

import (
	"testing"
	"time"
)

func TestClassifyCreate(t *testing.T) {
	at := time.Now()
	old := at.Add(-time.Hour)
	cases := []struct {
		name        string
		disposition uint32
		exists      bool
		created     time.Time
		want        string
		ok          bool
	}{
		{"plain open of existing file", fileOpen, true, old, "", false},
		{"explicit create", fileCreate, true, at, "created", true},
		{"open-if on existing file (append)", fileOpenIf, true, old, "", false},
		{"open-if that created the file", fileOpenIf, true, at.Add(-time.Second), "created", true},
		{"open-if before the file is visible", fileOpenIf, false, time.Time{}, "created", true},
		{"overwrite existing", fileOverwriteIf, true, old, "overwritten", true},
		{"supersede new", fileSupersede, true, at, "created", true},
	}
	for _, c := range cases {
		got, ok := classifyCreate(c.disposition, c.exists, c.created, at)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestTempPolicyKeepsDroppedExecutables(t *testing.T) {
	if isNoisyFilePath(`c:\users\bob\appdata\local\temp\payload.exe`) {
		t.Error("an executable dropped in Temp must be reported")
	}
	if isNoisyFilePath(`c:\windows\temp\run.ps1`) {
		t.Error("a script dropped in Windows/Temp must be reported")
	}
	if !isNoisyFilePath(`c:\users\bob\appdata\local\temp\cache123.dat`) {
		t.Error("ordinary temp data stays filtered")
	}
	if !isNoisyFilePath(`c:\windows\prefetch\cmd.exe-123.pf`) {
		t.Error("non-temp noise list still applies")
	}
}

func TestFileObjectPathsResolveAndBound(t *testing.T) {
	m := newFileObjectPaths(2, time.Hour)
	m.put(1, `c:\a.txt`)
	m.put(2, `c:\b.txt`)
	m.put(3, `c:\c.txt`) // rotates: 1 and 2 move to the previous generation
	if m.get(1) != `c:\a.txt` || m.get(3) != `c:\c.txt` {
		t.Fatal("entries must survive one rotation")
	}
	m.put(4, `c:\d.txt`)
	m.put(5, `c:\e.txt`) // second rotation drops the oldest generation
	if m.get(1) != "" {
		t.Fatal("old generation must be evicted (bounded memory)")
	}
	m.forget(5)
	if m.get(5) != "" {
		t.Fatal("forget removes the mapping")
	}
}
