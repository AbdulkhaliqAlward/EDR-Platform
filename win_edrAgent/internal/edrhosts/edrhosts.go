// Package edrhosts holds the single, tested implementation of removing the
// agent's own entries from the Windows hosts file. It is shared by the online
// uninstall cleanup (command package) and the offline uninstall path (agent
// entry point), so the parsing logic exists in exactly one place.
//
// Platform-neutral and dependency-free so it can be unit-tested anywhere.
package edrhosts

import "strings"

// Path is the canonical Windows hosts file location.
const Path = `C:\Windows\System32\drivers\etc\hosts`

// Markers the agent writes into the hosts file. These MUST match what the
// installer (C2 mapping) and the blockDomain response action write.
const (
	C2Marker       = "# EDR C2"
	BlockBeginMark = "# EDR_BLOCK_BEGIN "
	BlockEndMark   = "# EDR_BLOCK_END "
)

// StripEntries removes the lines the agent added to the hosts file: the
// "# EDR C2" server mapping and every "# EDR_BLOCK_BEGIN/END <domain>" sinkhole
// block. Inside a block only the agent's own "127.0.0.1 <domain>" line is
// dropped, so any unrelated content that ended up between the markers is kept.
// Returns the cleaned content and whether anything changed.
func StripEntries(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	changed := false
	blockDomain := ""

	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case strings.Contains(line, C2Marker):
			changed = true
		case strings.HasPrefix(t, BlockBeginMark):
			blockDomain = strings.TrimSpace(strings.TrimPrefix(t, BlockBeginMark))
			changed = true
		case strings.HasPrefix(t, BlockEndMark):
			blockDomain = ""
			changed = true
		case blockDomain != "" && strings.EqualFold(strings.Join(strings.Fields(t), " "), "127.0.0.1 "+blockDomain):
			changed = true
		default:
			out = append(out, line)
		}
	}
	if !changed {
		return content, false
	}
	return strings.Join(out, "\n"), true
}
