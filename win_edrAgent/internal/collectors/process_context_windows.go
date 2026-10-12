//go:build windows
// +build windows

package collectors

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// Process context for events raised BY a process (image loads, network
// connections, DNS queries, named pipes…).
//
// Detection, alert display and response all need the acting process: its
// image, command line, parent, user and start time (the start time pins the
// process generation, so a response never acts on a reused PID). A live
// OpenProcess at event time fails for processes that already exited — the
// common case for short-lived tools — so the agent's process table, filled
// from kernel process-creation events and kept for a few minutes after exit,
// is the primary source. A live query is only the fallback.

// processContextAt returns the record describing pid at time at, or nil when
// the table has no record for that process generation.
func processContextAt(pid uint32, at time.Time) *procRecord {
	if pid == 0 || pid == 4 {
		return nil
	}
	r := procTable.get(pid)
	if r == nil {
		return nil
	}
	if !r.created.IsZero() && r.created.After(at.Add(creationTolerance)) {
		return nil // a newer process reused the PID after this event
	}
	if !r.exited.IsZero() && at.After(r.exited.Add(creationTolerance)) {
		return nil // the recorded process had already exited
	}
	return r
}

// enrichProcessContext fills the acting-process fields of data that are
// missing or empty. Existing collector values are never overwritten.
// Fields: executable/process_path/Image, process_name, command_line, ppid,
// parent_executable/parent_name, process_start_time, user_name, user_sid,
// integrity_level, is_elevated.
func enrichProcessContext(data map[string]interface{}, pid uint32, at time.Time) {
	if data == nil || pid == 0 || pid == 4 {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	image, cmdline := "", ""
	var ppid uint32
	var started time.Time
	user, sid, integrity := "", "", ""
	elevated, haveToken := false, false

	if r := processContextAt(pid, at); r != nil {
		image, cmdline, ppid, started = r.image, r.cmdline, r.ppid, r.created
		user, sid, integrity, elevated = r.user, r.userSid, r.integrity, r.elevated
		haveToken = r.userSid != "" || r.user != ""
	}
	// Live fallback only for the same generation: a process started after the
	// event is a different process that reused the PID.
	if live := processCreateTime(pid); !live.IsZero() && !live.After(at.Add(creationTolerance)) && (started.IsZero() || live.Equal(started)) {
		if image == "" {
			image = getImagePath(pid)
		}
		if cmdline == "" {
			cmdline = getCmdLine(pid)
		}
		if started.IsZero() {
			started = live
		}
		if !haveToken {
			sid, user, elevated, integrity = getPrivileges(pid)
			haveToken = sid != "" || user != ""
		}
	}

	setIfEmpty(data, "executable", image)
	setIfEmpty(data, "process_path", image)
	setIfEmpty(data, "Image", image)
	if name := baseName(image); name != "" {
		if v, _ := data["process_name"].(string); v == "" || strings.EqualFold(v, "unknown") {
			data["process_name"] = name
		}
	}
	setIfEmpty(data, "command_line", cmdline)
	if ppid != 0 {
		if _, ok := data["ppid"]; !ok {
			data["ppid"] = ppid
		}
		if parent := processContextAt(ppid, started); parent != nil {
			setIfEmpty(data, "parent_executable", parent.image)
			setIfEmpty(data, "parent_name", baseName(parent.image))
		}
	}
	if !started.IsZero() {
		setIfEmpty(data, "process_start_time", started.UTC().Format(time.RFC3339Nano))
	}
	if haveToken {
		setIfEmpty(data, "user_name", user)
		setIfEmpty(data, "user_sid", sid)
		setIfEmpty(data, "integrity_level", integrity)
		if _, ok := data["is_elevated"]; !ok {
			data["is_elevated"] = elevated
		}
	}
}

func setIfEmpty(data map[string]interface{}, key, value string) {
	if value == "" {
		return
	}
	if cur, ok := data[key]; ok {
		if s, isStr := cur.(string); !isStr || (s != "" && !strings.EqualFold(s, "unknown")) {
			return
		}
	}
	data[key] = value
}

// imagePathAt returns the image of pid at time at: the live process when it is
// the same generation, else the process table (exited processes).
func imagePathAt(pid uint32, at time.Time) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	r := processContextAt(pid, at)
	if live := processCreateTime(pid); !live.IsZero() && !live.After(at.Add(creationTolerance)) && (r == nil || r.created.IsZero() || live.Equal(r.created)) {
		if p := getImagePath(pid); p != "" {
			return p
		}
	}
	if r != nil {
		return r.image
	}
	return ""
}

var (
	sidAccountMu    sync.Mutex
	sidAccountCache = map[string]string{}
)

// accountForSID resolves "S-1-5-…" to DOMAIN\user (cached; SIDs of local and
// domain accounts resolve without network for cached logons). Returns "" when
// the SID cannot be resolved.
func accountForSID(sid string) string {
	if sid == "" {
		return ""
	}
	sidAccountMu.Lock()
	if v, ok := sidAccountCache[sid]; ok {
		sidAccountMu.Unlock()
		return v
	}
	sidAccountMu.Unlock()
	name := ""
	if s, err := windows.StringToSid(sid); err == nil {
		if account, domain, _, err := s.LookupAccount(""); err == nil && account != "" {
			name = account
			if domain != "" {
				name = domain + `\` + account
			}
		}
	}
	sidAccountMu.Lock()
	if len(sidAccountCache) > 4096 {
		sidAccountCache = map[string]string{}
	}
	sidAccountCache[sid] = name
	sidAccountMu.Unlock()
	return name
}
