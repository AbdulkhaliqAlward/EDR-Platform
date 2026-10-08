// Package response implements the server-side response engine: automated
// triggering of playbooks from Sigma alerts, playbook suggestions, alert
// context binding and tracked, sequential execution of playbook steps on
// agents.
package response

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/commandtypes"
)

// AlertVars is the flat variable set extracted from an alert, keyed by the
// names usable in templates as {{alert.<name>}}.
type AlertVars map[string]string

// VariableNames lists the documented alert variables (for the UI).
var VariableNames = []string{
	"id", "agent_id", "rule_id", "rule_title", "severity", "risk_score", "category", "hostname",
	"process_name", "pid", "process_path", "command_line", "parent_process_path", "user",
	"file_path", "sha256", "destination_ip", "destination_port", "source_ip", "domain", "registry_key",
}

// legacyAliases maps the ${name} placeholders used by seeded playbooks.
var legacyAliases = map[string]string{
	"malware_process":    "process_name",
	"ransomware_process": "process_name",
	"process_name":       "process_name",
	"malware_file":       "file_path",
	"suspicious_file":    "file_path",
	"file_path":          "file_path",
	"pid":                "pid",
	"ip":                 "destination_ip",
	"domain":             "domain",
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// scalar renders a JSON scalar as text ("" for maps, arrays and nil).
func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

// NormalizeAgentID strips the "agent-" certificate prefix used in some places.
func NormalizeAgentID(id string) string {
	id = strings.TrimSpace(id)
	return strings.TrimPrefix(strings.TrimPrefix(id, "agent-"), "AGENT-")
}

// BuildAlertVars extracts template variables from a Sigma alert: alert
// metadata, the raw agent event (context_data, with its data.* fields) and
// the Sigma-named matched fields.
func BuildAlertVars(a *repository.SigmaAlertRecord) AlertVars {
	v := AlertVars{
		"id":         a.ID,
		"agent_id":   NormalizeAgentID(a.AgentID),
		"rule_id":    a.RuleID,
		"rule_title": a.RuleTitle,
		"severity":   strings.ToLower(a.Severity),
		"risk_score": strconv.Itoa(a.RiskScore),
		"category":   a.Category,
	}
	ctx := a.ContextData
	data := asMap(ctx["data"])
	mf := a.MatchedFields
	eventType := strings.ToLower(scalar(ctx["event_type"]))

	first := func(vals ...string) string {
		for _, s := range vals {
			if s != "" {
				return s
			}
		}
		return ""
	}
	d := func(k string) string { return scalar(data[k]) }
	m := func(k string) string { return scalar(mf[k]) }

	v["hostname"] = first(scalar(asMap(ctx["source"])["hostname"]), d("hostname"), scalar(ctx["hostname"]))
	v["process_path"] = first(d("executable"), d("process_path"), m("Image"))
	// On process events "name" is the image name; on file/registry events it
	// is the target's name and the actor is in process_name.
	if eventType == "process" {
		v["process_name"] = first(d("name"), d("process_name"))
	} else {
		v["process_name"] = d("process_name")
	}
	if v["process_name"] == "" && v["process_path"] != "" {
		v["process_name"] = path.Base(strings.ReplaceAll(v["process_path"], `\`, "/"))
	}
	v["pid"] = first(d("pid"), m("ProcessId"))
	v["command_line"] = first(d("command_line"), m("CommandLine"))
	v["parent_process_path"] = first(d("parent_executable"), m("ParentImage"))
	v["user"] = first(d("user_name"), m("User"))
	if eventType == "file" {
		v["file_path"] = first(d("path"), d("target_filename"), m("TargetFilename"))
	} else {
		// Process alerts: the file to scan/quarantine is the process image.
		v["file_path"] = first(d("target_filename"), m("TargetFilename"), v["process_path"])
	}
	v["sha256"] = first(d("sha256"), d("hash_sha256"), sha256FromHashes(first(d("hashes"), m("Hashes"))))
	v["destination_ip"] = first(d("destination_ip"), m("DestinationIp"))
	v["destination_port"] = first(d("destination_port"), m("DestinationPort"))
	v["source_ip"] = first(d("source_ip"), m("SourceIp"))
	v["domain"] = first(d("query_name"), m("QueryName"), m("DestinationHostname"))
	v["registry_key"] = first(d("TargetObject"), d("key_path"), m("TargetObject"))

	// Any other scalar data.* field is available as {{alert.data.<key>}}.
	for k, val := range data {
		if s := scalar(val); s != "" {
			v["data."+k] = s
		}
	}
	for k, val := range v {
		if val == "" {
			delete(v, k)
		}
	}
	return v
}

func sha256FromHashes(h string) string {
	for _, part := range strings.Split(h, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "SHA256") {
			return strings.ToLower(strings.TrimSpace(kv[1]))
		}
	}
	return ""
}

var (
	templateRe = regexp.MustCompile(`\{\{\s*alert\.([A-Za-z0-9_.]+)\s*\}\}`)
	legacyRe   = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
)

// hasTemplate reports whether s contains a template reference.
func hasTemplate(s string) bool {
	return templateRe.MatchString(s) || legacyRe.MatchString(s)
}

// resolveTemplates substitutes alert variables. It returns the names of
// variables that could not be resolved.
func resolveTemplates(s string, vars AlertVars) (string, []string) {
	var missing []string
	out := templateRe.ReplaceAllStringFunc(s, func(m string) string {
		name := templateRe.FindStringSubmatch(m)[1]
		if val, ok := vars[name]; ok {
			return val
		}
		missing = append(missing, name)
		return m
	})
	out = legacyRe.ReplaceAllStringFunc(out, func(m string) string {
		raw := legacyRe.FindStringSubmatch(m)[1]
		name, ok := legacyAliases[raw]
		if !ok {
			missing = append(missing, raw)
			return m
		}
		if val, ok := vars[name]; ok {
			return val
		}
		missing = append(missing, name)
		return m
	})
	return out, missing
}

// actionParam describes a parameter of a built-in response action.
type actionParam struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
	AlertVar string `json:"alert_var,omitempty"` // auto-filled from this alert variable when empty
	Kind     string `json:"kind"`                // pid | path | ip | domain | int | text | log_channels
}

// Action is a built-in response action that playbooks may use.
type Action struct {
	Type        string        `json:"type"`
	Label       string        `json:"label"`
	Group       string        `json:"group"`
	Description string        `json:"description"`
	Params      []actionParam `json:"params"`
	Destructive bool          `json:"destructive"`
}

// Actions is the approved catalog of built-in playbook actions. Every type
// maps to an agent command (commandtypes.ToProto). run_cmd is deliberately
// absent: commands come from the admin-curated script library (run_script).
var Actions = []Action{
	{Type: "isolate_network", Label: "Isolate host from network", Group: "Containment", Destructive: true,
		Description: "Block all traffic except the EDR server."},
	{Type: "unisolate_network", Label: "Restore network access", Group: "Containment",
		Description: "Remove network isolation."},
	{Type: "terminate_process", Label: "Terminate process", Group: "Containment", Destructive: true,
		Description: "Kill the alert's process (and optionally its tree).",
		Params: []actionParam{
			{Key: "pid", Label: "Process ID", Required: true, AlertVar: "pid", Kind: "pid"},
			{Key: "kill_tree", Label: "Kill process tree (true/false)", Kind: "bool"},
		}},
	{Type: "quarantine_file", Label: "Quarantine file", Group: "Containment", Destructive: true,
		Description: "Move the file into the agent's quarantine.",
		Params:      []actionParam{{Key: "file_path", Label: "File path", Required: true, AlertVar: "file_path", Kind: "path"}}},
	{Type: "block_ip", Label: "Block IP", Group: "Containment",
		Params: []actionParam{{Key: "ip", Label: "IP address", Required: true, AlertVar: "destination_ip", Kind: "ip"}}},
	{Type: "block_domain", Label: "Block domain", Group: "Containment",
		Params: []actionParam{{Key: "domain", Label: "Domain", Required: true, AlertVar: "domain", Kind: "domain"}}},
	{Type: "scan_file", Label: "Scan file / folder", Group: "Investigation",
		Params: []actionParam{{Key: "file_path", Label: "Path to scan", Required: true, AlertVar: "file_path", Kind: "path"}}},
	{Type: "collect_logs", Label: "Collect event logs", Group: "Investigation",
		Params: []actionParam{{Key: "log_types", Label: "Log channels", Kind: "log_channels"}}},
	{Type: "collect_forensics", Label: "Collect forensics package", Group: "Investigation",
		Params: []actionParam{
			{Key: "log_types", Label: "Log channels", Kind: "log_channels"},
			{Key: "max_events", Label: "Max events", Kind: "int"},
		}},
	{Type: "process_tree_snapshot", Label: "Process tree snapshot", Group: "Investigation"},
	{Type: "persistence_scan", Label: "Persistence scan", Group: "Investigation"},
	{Type: "lsass_access_audit", Label: "LSASS access audit", Group: "Investigation"},
	{Type: "network_last_seen", Label: "Recent network connections", Group: "Investigation"},
	{Type: "filesystem_timeline", Label: "Filesystem timeline", Group: "Investigation",
		Params: []actionParam{{Key: "window_hours", Label: "Time window (hours)", Kind: "int"}}},
	{Type: "memory_dump", Label: "Memory dump", Group: "Investigation"},
	{Type: "agent_integrity_check", Label: "Agent integrity check", Group: "Validation"},
	{Type: "update_signatures", Label: "Update signatures", Group: "Remediation"},
	{Type: "run_script", Label: "Run library script", Group: "Remediation",
		Description: "Run an admin-approved script from the response script library."},
}

var actionByType = func() map[string]*Action {
	m := make(map[string]*Action, len(Actions))
	for i := range Actions {
		m[Actions[i].Type] = &Actions[i]
	}
	return m
}()

// legacyTypes maps old/alias step types to catalog types.
var legacyTypes = map[string]string{
	"process_terminate": "terminate_process",
	"kill_process":      "terminate_process",
	"network_isolate":   "isolate_network",
	"isolate":           "isolate_network",
	"restore_network":   "unisolate_network",
	"unisolate":         "unisolate_network",
	"yara_scan":         "scan_file",
	"log_pull":          "collect_logs",
	"forensic_dump":     "collect_forensics",
}

// CanonicalType resolves a step type to its catalog type ("run_cmd" stays
// run_cmd: it is accepted only for legacy, already-stored playbooks).
func CanonicalType(t string) string {
	t = commandtypes.Normalize(t)
	if c, ok := legacyTypes[t]; ok {
		return c
	}
	return t
}

// ActionFor returns the catalog entry for a step type, if any.
func ActionFor(stepType string) (*Action, bool) {
	a, ok := actionByType[CanonicalType(stepType)]
	return a, ok
}

var domainRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\.?$`)

// validateParam checks a bound value against its kind.
func validateParam(p actionParam, val string) error {
	if commandtypes.HasControlChars(val) {
		return fmt.Errorf("%s contains control characters", p.Label)
	}
	switch p.Kind {
	case "pid":
		n, err := strconv.Atoi(val)
		if err != nil || n <= 4 { // 0/4 are System/Idle; never terminate them
			return fmt.Errorf("%s must be a process ID greater than 4 (got %q)", p.Label, val)
		}
	case "ip":
		if net.ParseIP(val) == nil {
			return fmt.Errorf("%s must be a valid IP address (got %q)", p.Label, val)
		}
	case "domain":
		if !domainRe.MatchString(val) {
			return fmt.Errorf("%s must be a valid domain name (got %q)", p.Label, val)
		}
	case "int":
		if n, err := strconv.Atoi(val); err != nil || n <= 0 {
			return fmt.Errorf("%s must be a positive whole number (got %q)", p.Label, val)
		}
	case "bool":
		if !strings.EqualFold(val, "true") && !strings.EqualFold(val, "false") {
			return fmt.Errorf("%s must be true or false", p.Label)
		}
	case "path":
		if len(val) > 1024 {
			return fmt.Errorf("%s is too long", p.Label)
		}
	}
	return nil
}

// sortedKeys returns map keys sorted (deterministic output).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
