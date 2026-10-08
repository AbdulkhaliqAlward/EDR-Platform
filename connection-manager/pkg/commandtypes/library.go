package commandtypes

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxLibraryCommandLen bounds a library (run_cmd) command line.
const MaxLibraryCommandLen = 4096

// EjectUSBToken is the agent's native USB-eject action (see agent runCommand).
const EjectUSBToken = "__EJECT_USB__"

// LibraryExecutables mirrors the agent's playbookAllowedCommands
// (win_edrAgent/internal/command/handler.go). The agent remains the authority;
// this copy lets the server reject a command when it is authored instead of
// it failing on every endpoint. Keep the two lists in sync.
var LibraryExecutables = map[string]bool{
	"ping": true, "tracert": true, "pathping": true, "netstat": true, "ipconfig": true,
	"nslookup": true, "whoami": true, "hostname": true, "systeminfo": true, "tasklist": true,
	"arp": true, "route": true,
	"powershell": true, "cmd": true, "sc": true, "net": true, "reg": true, "wmic": true,
	"attrib": true, "wevtutil": true, "icacls": true, "mountvol": true,
}

// LibraryExecutableNames returns the allowed executables, sorted.
func LibraryExecutableNames() []string {
	names := make([]string, 0, len(LibraryExecutables))
	for k := range LibraryExecutables {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ParseAgentCommandLine tokenizes exactly like the agent's parseCommandLine:
// split on spaces outside double quotes; quote characters are dropped.
func ParseAgentCommandLine(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// HasControlChars reports whether s contains ASCII control characters
// (newlines and tabs included) or invalid UTF-8.
func HasControlChars(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ValidateLibraryCommand checks a command line against the agent's
// library-tier rules plus stricter server-side rules (bare executable name,
// no powershell -File / -EncodedCommand, single line).
func ValidateLibraryCommand(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return errors.New("command is required")
	}
	if len(cmd) > MaxLibraryCommandLen {
		return fmt.Errorf("command is too long (max %d characters)", MaxLibraryCommandLen)
	}
	if HasControlChars(cmd) {
		return errors.New("command must be a single line without tabs or control characters")
	}
	if strings.EqualFold(cmd, EjectUSBToken) {
		return nil
	}
	if strings.Count(cmd, `"`)%2 != 0 {
		return errors.New("command has unbalanced double quotes")
	}
	parts := ParseAgentCommandLine(cmd)
	if len(parts) == 0 {
		return errors.New("command is empty after parsing")
	}
	exe := parts[0]
	// Require a bare executable name. The agent resolves names via PATH; a path
	// (e.g. C:\Users\Public\powershell.exe) would run whatever file is there.
	if strings.ContainsAny(exe, `\/:`) {
		return fmt.Errorf("use the bare executable name (e.g. %q), not a path", "powershell")
	}
	name := strings.TrimSuffix(strings.ToLower(exe), ".exe")
	if !LibraryExecutables[name] {
		return fmt.Errorf("%q is not an allowed executable. Allowed: %s", exe, strings.Join(LibraryExecutableNames(), ", "))
	}
	if name == "powershell" {
		for _, arg := range parts[1:] {
			argL := strings.ToLower(strings.TrimLeft(arg, "-/"))
			if argL == "file" || argL == "f" {
				return errors.New("powershell -File is not permitted; use -Command with an inline script")
			}
			if argL == "encodedcommand" || argL == "ec" || argL == "en" || argL == "enc" {
				return errors.New("powershell -EncodedCommand is not permitted")
			}
		}
	}
	return nil
}
