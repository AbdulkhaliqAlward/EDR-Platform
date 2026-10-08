//go:build windows
// +build windows

package responder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// ProcessRulePack is a file-backed pack of process response rules.
type ProcessRulePack struct {
	Version string        `json:"version"`
	Rules   []ProcessRule `json:"rules"`
}

// ProcessRule defines one process creation response rule.
type ProcessRule struct {
	ID       string                `json:"id"`
	Title    string                `json:"title"`
	Enabled  bool                  `json:"enabled"`
	Severity string                `json:"severity"`
	Action   string                `json:"action"`
	Match    ProcessRuleMatch      `json:"match"`
	Response ProcessRuleActionConf `json:"response"`
}

// ProcessRuleMatch describes matching conditions against normalized process event fields.
type ProcessRuleMatch struct {
	ParentNameAny            []string `json:"parent_name_any"`
	NameAny                  []string `json:"name_any"`
	CommandLineContainsAny   []string `json:"command_line_contains_any"`
	CommandLineContainsAll   []string `json:"command_line_contains_all"`
	ParentExecutableContains []string `json:"parent_executable_contains"`
}

// ProcessRuleActionConf controls endpoint action behavior.
type ProcessRuleActionConf struct {
	KillTree        bool `json:"kill_tree"`
	CooldownSeconds int  `json:"cooldown_seconds"`
}

// ProcessEngine executes local process auto-response decisions using a rule pack.
type ProcessEngine struct {
	logger         *logging.Logger
	enabled        bool
	preventionMode string
	rules          []ProcessRule
	criticalNames  map[string]struct{}
	lastMatch      map[string]time.Time
	mu             sync.Mutex
	terminate      func(context.Context, map[string]string) (string, error)
}

// SetTerminator wires the identity-checked command implementation before use.
// Local prevention never falls back to PID-only taskkill.
func (e *ProcessEngine) SetTerminator(fn func(context.Context, map[string]string) (string, error)) {
	e.terminate = fn
}

// NewProcessEngine loads and validates a process rule pack from disk.
func NewProcessEngine(logger *logging.Logger, rulesPath, preventionMode string, enabled bool) (*ProcessEngine, error) {
	e := &ProcessEngine{
		logger:         logger,
		enabled:        enabled,
		preventionMode: strings.ToLower(strings.TrimSpace(preventionMode)),
		criticalNames: map[string]struct{}{
			"system":        {},
			"smss.exe":      {},
			"csrss.exe":     {},
			"wininit.exe":   {},
			"winlogon.exe":  {},
			"services.exe":  {},
			"lsass.exe":     {},
			"svchost.exe":   {},
			"dwm.exe":       {},
			"edr-agent.exe": {},
			"agent.exe":     {},
		},
		lastMatch: make(map[string]time.Time, 128),
	}
	if !enabled {
		return e, nil
	}
	if strings.TrimSpace(rulesPath) == "" {
		return nil, fmt.Errorf("process rules path is empty")
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("read process rules pack: %w", err)
	}
	var pack ProcessRulePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse process rules pack: %w", err)
	}
	for _, r := range pack.Rules {
		if !r.Enabled || strings.TrimSpace(r.ID) == "" {
			continue
		}
		if strings.TrimSpace(r.Action) == "" {
			r.Action = "terminate"
		}
		if !strings.EqualFold(strings.TrimSpace(r.Action), "terminate") {
			return nil, fmt.Errorf("unsupported process response action %q in rule %s", r.Action, r.ID)
		}
		if r.Response.CooldownSeconds <= 0 {
			r.Response.CooldownSeconds = 60
		}
		e.rules = append(e.rules, r)
	}
	if len(e.rules) == 0 {
		return nil, fmt.Errorf("no enabled process response rules in pack: %s", filepath.Base(rulesPath))
	}
	logger.Infof("[Response] Process rules loaded: %d enabled (pack=%s version=%s)", len(e.rules), rulesPath, pack.Version)
	return e, nil
}

// EnsureDefaultProcessRulesFile writes the embedded starter rule pack when the file is missing or empty,
// so process auto-response works after install without deploying JSON separately (operators may overwrite later).
func EnsureDefaultProcessRulesFile(path string, logger *logging.Logger) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("process rules path is empty")
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return nil
	}
	if len(defaultProcessRulesJSON) == 0 {
		return fmt.Errorf("embedded default process rules unavailable")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir rules dir: %w", err)
	}
	if err := os.WriteFile(path, defaultProcessRulesJSON, 0644); err != nil {
		return fmt.Errorf("write default rules: %w", err)
	}
	if logger != nil {
		logger.Infof("[Response] Installed default process rule pack → %s", path)
	}
	return nil
}

// EvaluateAndAct applies process rules and performs local terminate action when matched.
func (e *ProcessEngine) EvaluateAndAct(ctx context.Context, base map[string]interface{}) (*event.Event, bool) {
	if e == nil || !e.enabled || len(e.rules) == 0 {
		return nil, false
	}
	name := lowerString(base["name"])
	if name == "" {
		name = lowerString(base["process_name"])
	}
	if name == "" {
		return nil, false
	}
	if _, protected := e.criticalNames[name]; protected {
		return nil, false
	}

	for _, rule := range e.rules {
		if !matchesRule(rule.Match, base) {
			continue
		}
		if e.inCooldown(rule, base) {
			continue
		}

		sev := toSeverity(rule.Severity)
		if e.preventionMode != "auto_kill_then_override" {
			evt := event.NewEvent(event.EventTypeProcess, sev, mergeProcessResponseData(base, map[string]interface{}{
				"action":             "process_rule_matched_detect_only",
				"autonomous":         true,
				"decision_mode":      e.preventionMode,
				"matched_rule_id":    rule.ID,
				"matched_rule_title": rule.Title,
				"response_action":    "detect_only",
			}))
			return evt, true
		}

		pid := toUint32(base["pid"])
		if pid == 0 {
			evt := event.NewEvent(event.EventTypeProcess, sev, mergeProcessResponseData(base, map[string]interface{}{
				"action":             "process_rule_match_no_pid",
				"autonomous":         true,
				"decision_mode":      e.preventionMode,
				"matched_rule_id":    rule.ID,
				"matched_rule_title": rule.Title,
				"response_action":    "terminate",
			}))
			return evt, true
		}
		out, err := e.terminateMeasured(ctx, pid, base, rule.Response.KillTree)
		if err != nil {
			evt := event.NewEvent(event.EventTypeProcess, event.SeverityHigh, mergeProcessResponseData(base, map[string]interface{}{
				"action":             "auto_terminate_failed",
				"autonomous":         true,
				"decision_mode":      e.preventionMode,
				"matched_rule_id":    rule.ID,
				"matched_rule_title": rule.Title,
				"response_action":    "terminate",
				"kill_tree":          rule.Response.KillTree,
				"kill_error":         err.Error(),
				"kill_output":        out,
			}))
			return evt, true
		}
		evt := event.NewEvent(event.EventTypeProcess, sev, mergeProcessResponseData(base, map[string]interface{}{
			"action":             "auto_terminated",
			"autonomous":         true,
			"decision_mode":      e.preventionMode,
			"matched_rule_id":    rule.ID,
			"matched_rule_title": rule.Title,
			"response_action":    "terminate",
			"kill_tree":          rule.Response.KillTree,
			"kill_output":        out,
		}))
		e.logger.Warnf("[Response] AUTO-TERMINATED pid=%d name=%s rule=%s", pid, name, rule.ID)
		return evt, true
	}
	return nil, false
}

func matchesRule(m ProcessRuleMatch, base map[string]interface{}) bool {
	parentName := lowerString(base["parent_name"])
	name := lowerString(base["name"])
	cmd := lowerString(base["command_line"])
	parentExe := lowerString(base["parent_executable"])

	if len(m.ParentNameAny) > 0 && !containsAnyEq(parentName, m.ParentNameAny) {
		return false
	}
	if len(m.NameAny) > 0 && !containsAnyEq(name, m.NameAny) {
		return false
	}
	if len(m.CommandLineContainsAny) > 0 && !containsAnySubstr(cmd, m.CommandLineContainsAny) {
		return false
	}
	if len(m.CommandLineContainsAll) > 0 && !containsAllSubstr(cmd, m.CommandLineContainsAll) {
		return false
	}
	if len(m.ParentExecutableContains) > 0 && !containsAnySubstr(parentExe, m.ParentExecutableContains) {
		return false
	}
	return true
}

func (e *ProcessEngine) inCooldown(rule ProcessRule, base map[string]interface{}) bool {
	key := fmt.Sprintf("%s|%v|%v", rule.ID, base["pid"], base["process_start_time"])
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.lastMatch) >= 4096 {
		for key, at := range e.lastMatch {
			if now.Sub(at) > time.Hour {
				delete(e.lastMatch, key)
			}
		}
		if len(e.lastMatch) >= 4096 {
			for key := range e.lastMatch {
				delete(e.lastMatch, key)
				break
			}
		}
	}
	last, ok := e.lastMatch[key]
	if ok && now.Sub(last) < time.Duration(rule.Response.CooldownSeconds)*time.Second {
		return true
	}
	e.lastMatch[key] = now
	return false
}

func (e *ProcessEngine) terminateMeasured(ctx context.Context, pid uint32, base map[string]interface{}, killTree bool) (string, error) {
	image, _ := base["executable"].(string)
	started, _ := base["process_start_time"].(string)
	if pid <= 4 || strings.TrimSpace(image) == "" || strings.TrimSpace(started) == "" {
		return "", fmt.Errorf("local termination requires a measured process image and creation time")
	}
	if _, err := time.Parse(time.RFC3339Nano, started); err != nil {
		return "", fmt.Errorf("invalid measured process creation time: %w", err)
	}
	if e.terminate == nil {
		return "", fmt.Errorf("identity-checked local terminator is unavailable")
	}
	return e.terminate(ctx, map[string]string{
		"pid": fmt.Sprint(pid), "kill_tree": fmt.Sprint(killTree),
		"process_path": image, "process_started_at": started,
	})
}

func toSeverity(s string) event.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return event.SeverityCritical
	case "high":
		return event.SeverityHigh
	case "medium":
		return event.SeverityMedium
	default:
		return event.SeverityLow
	}
}

func mergeProcessResponseData(base, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, len(base)+len(extra))
	for k, v := range base {
		data[k] = v
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func lowerString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
}

func toUint32(v interface{}) uint32 {
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int:
		if n < 0 {
			return 0
		}
		return uint32(n)
	case int64:
		if n < 0 {
			return 0
		}
		return uint32(n)
	case float64:
		if n < 0 {
			return 0
		}
		return uint32(n)
	default:
		return 0
	}
}

func containsAnyEq(val string, options []string) bool {
	for _, opt := range options {
		if strings.EqualFold(strings.TrimSpace(opt), val) {
			return true
		}
	}
	return false
}

func containsAnySubstr(val string, options []string) bool {
	for _, opt := range options {
		if strings.Contains(val, strings.ToLower(strings.TrimSpace(opt))) {
			return true
		}
	}
	return false
}

func containsAllSubstr(val string, options []string) bool {
	for _, opt := range options {
		if !strings.Contains(val, strings.ToLower(strings.TrimSpace(opt))) {
			return false
		}
	}
	return true
}
