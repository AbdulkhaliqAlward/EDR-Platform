package detection

import (
	"strings"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

// agentInstallPaths are the EDR agent's canonical, ACL-protected executable
// locations (without the drive letter, lower-case). Events whose parent
// process is exactly one of these are the agent's own helper activity and are
// suppressed as a defense-in-depth layer behind the agent's own
// process-ancestry self-filter.
//
// Matching is by exact full path only. A bare file name ("edr-agent.exe") or
// a path that merely ends with it (C:\Users\x\edr-agent.exe) is attacker
// controllable and must never hide telemetry.
var agentInstallPaths = map[string]struct{}{
	`\programdata\edr\bin\edr-agent.exe`: {},
	`\programdata\edr\bin\agent.exe`:     {},
	`\program files\edr\edr-agent.exe`:   {},
	`\program files\edr\agent.exe`:       {},
}

// parentFieldPaths are the fields carrying the parent's full image path.
var parentFieldPaths = []string{
	"parent_executable",
	"parent_image",
	"ParentImage",
	"parent_path",
}

// isAgentInstallPath reports whether p is "<drive>:" + a canonical path.
func isAgentInstallPath(p string) bool {
	v := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "/", `\`)))
	v = strings.TrimPrefix(v, `\\?\`)
	if len(v) < 3 || v[1] != ':' || v[0] < 'a' || v[0] > 'z' {
		return false
	}
	_, ok := agentInstallPaths[v[2:]]
	return ok
}

// isAgentSelfEvent reports whether the event was produced by a process the
// EDR agent itself started (its parent is the agent at its install path).
func isAgentSelfEvent(event *domain.LogEvent) bool {
	if event == nil {
		return false
	}
	for _, path := range parentFieldPaths {
		if raw := event.GetStringField(path); raw != "" && isAgentInstallPath(raw) {
			return true
		}
	}
	return false
}
