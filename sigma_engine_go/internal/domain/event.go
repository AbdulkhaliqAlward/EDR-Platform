package domain

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LogEvent represents a normalized security event in ECS (Elastic Common Schema) format.
// It provides efficient field access with caching and automatic category inference.
// Thread-safe for concurrent field access.
type LogEvent struct {
	RawData map[string]interface{} `json:"raw_data"`

	// EventID is the event's record identity (the agent assigns a UUID to
	// "event_id"). Alerts store it in event_ids so investigations can link
	// back to the source event. It is NOT the Windows/Sysmon event code.
	EventID *string `json:"event_id,omitempty"`

	// EventCode is the numeric provider event code (Sysmon 1, Security 4688…)
	// when the event carries one. It is never derived from the record UUID.
	EventCode *int `json:"event_code,omitempty"`

	// Category is the primary Sigma logsource category; Categories adds the
	// generic parent categories the event must also be evaluated against.
	Category   EventCategory   `json:"category"`
	Categories []EventCategory `json:"categories,omitempty"`
	Product    string          `json:"product"`
	Service    string          `json:"service,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`

	fieldCache   map[string]interface{}
	cacheMu      sync.RWMutex
	hash         *string
	hashMu       sync.Mutex
	keywordBlob  string // lazily-computed lowercase JSON blob for keyword rules
	keywordOnce  sync.Once
	searchValues []string // lazily-computed lowercase string leaves for keyword search
	searchOnce   sync.Once

	// ack, when set by the transport (Kafka consumer), marks the event as
	// fully processed so its offset may be committed. Called once via Ack.
	ack     func()
	ackOnce sync.Once
}

// SetAck registers the transport's completion callback.
func (e *LogEvent) SetAck(fn func()) { e.ack = fn }

// Ack signals that processing of this event has finished (successfully or
// with a logged, non-retryable failure). Safe to call more than once.
func (e *LogEvent) Ack() {
	if e == nil || e.ack == nil {
		return
	}
	e.ackOnce.Do(e.ack)
}

// NewLogEvent creates a new LogEvent from raw event data.
// It extracts the record identity and provider event code, infers the Sigma
// category and service, and extracts product/timestamp.
// Returns an error if rawData is nil.
func NewLogEvent(rawData map[string]interface{}) (*LogEvent, error) {
	if rawData == nil {
		return nil, fmt.Errorf("rawData cannot be nil")
	}

	event := &LogEvent{
		RawData:    rawData,
		Category:   EventCategoryUnknown,
		Product:    "windows",
		Timestamp:  time.Now(),
		fieldCache: make(map[string]interface{}),
	}

	event.EventID = event.extractRecordID()
	event.EventCode = event.extractEventCode()
	event.Category = event.inferCategory()
	event.Categories = ExpandCategories(event.Category)
	event.Service = event.extractService()
	event.Product = event.extractProduct()
	event.Timestamp = event.extractTimestamp()

	return event, nil
}

// SearchValues returns every string leaf of the event (recursively, numbers
// and booleans included in their canonical text form), lowercased. It is
// computed once per event and backs Sigma keyword (full-text) selections.
// Unlike a JSON serialisation it preserves backslashes and quotes verbatim,
// so keywords such as `\Windows\Temp\` match the raw value.
func (e *LogEvent) SearchValues() []string {
	e.searchOnce.Do(func() {
		out := make([]string, 0, 32)
		var walk func(v interface{})
		walk = func(v interface{}) {
			switch t := v.(type) {
			case nil:
			case string:
				if t != "" {
					out = append(out, strings.ToLower(t))
				}
			case map[string]interface{}:
				for _, child := range t {
					walk(child)
				}
			case []interface{}:
				for _, child := range t {
					walk(child)
				}
			case []string:
				for _, child := range t {
					walk(child)
				}
			default:
				if s := ValueToString(t); s != "" {
					out = append(out, strings.ToLower(s))
				}
			}
		}
		walk(e.RawData)
		e.searchValues = out
	})
	return e.searchValues
}

// ValueToString renders a scalar event value in its canonical text form:
// integral floats without a fractional part or exponent (4688, not 4.688e+03).
func ValueToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

// GetField retrieves a field value by path with caching.
// Supports both flat ("EventID") and nested ("process.command_line") field paths.
// Thread-safe for concurrent access.
func (e *LogEvent) GetField(fieldPath string) (interface{}, bool) {
	e.cacheMu.RLock()
	if cached, ok := e.fieldCache[fieldPath]; ok {
		e.cacheMu.RUnlock()
		return cached, true
	}
	e.cacheMu.RUnlock()

	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := e.fieldCache[fieldPath]; ok {
		return cached, true
	}

	if val, ok := e.RawData[fieldPath]; ok && val != nil {
		e.fieldCache[fieldPath] = val
		return val, true
	}

	// Windows Agent specific fallback: search inside the "data" sub-map
	if sub, ok := e.RawData["data"]; ok && sub != nil {
		if m, ok := sub.(map[string]interface{}); ok {
			if val, ok := m[fieldPath]; ok && val != nil {
				e.fieldCache[fieldPath] = val
				return val, true
			}
		}
	}

	if val := e.getNested(fieldPath); val != nil {
		e.fieldCache[fieldPath] = val
		return val, true
	}

	e.fieldCache[fieldPath] = nil
	return nil, false
}

// GetStringField retrieves a field value as a string.
// Returns empty string if field is not found or cannot be converted.
func (e *LogEvent) GetStringField(fieldPath string) string {
	val, ok := e.GetField(fieldPath)
	if !ok || val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

// GetFloat64Field retrieves a field value as float64.
// Returns 0 and false if field is not found or cannot be converted.
func (e *LogEvent) GetFloat64Field(fieldPath string) (float64, bool) {
	val, ok := e.GetField(fieldPath)
	if !ok || val == nil {
		return 0, false
	}

	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// GetInt64Field retrieves a field value as int64.
// Returns 0 and false if field is not found or cannot be converted.
func (e *LogEvent) GetInt64Field(fieldPath string) (int64, bool) {
	val, ok := e.GetField(fieldPath)
	if !ok || val == nil {
		return 0, false
	}

	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case float64:
		return int64(v), true
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

// GetBoolField retrieves a field value as bool.
// Returns false and false if field is not found or cannot be converted.
func (e *LogEvent) GetBoolField(fieldPath string) (bool, bool) {
	val, ok := e.GetField(fieldPath)
	if !ok || val == nil {
		return false, false
	}

	switch v := val.(type) {
	case bool:
		return v, true
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b, true
		}
	}
	return false, false
}

// GetFieldWithDefault retrieves a field value or returns the default if not found.
func (e *LogEvent) GetFieldWithDefault(fieldPath string, defaultValue interface{}) interface{} {
	if val, ok := e.GetField(fieldPath); ok && val != nil {
		return val
	}
	return defaultValue
}

// HasField checks if a field exists and has a non-nil value.
func (e *LogEvent) HasField(fieldPath string) bool {
	val, ok := e.GetField(fieldPath)
	return ok && val != nil
}

// KeywordBlob returns a lazily-computed, lowercased JSON serialisation of
// RawData suitable for keyword rule full-text matching.
// The result is computed once per event (sync.Once) and shared by all keyword
// rule evaluations, eliminating repeated json.Marshal + strings.ToLower calls.
func (e *LogEvent) KeywordBlob() string {
	e.keywordOnce.Do(func() {
		b, err := json.Marshal(e.RawData)
		if err != nil {
			e.keywordBlob = ""
			return
		}
		e.keywordBlob = strings.ToLower(string(b))
	})
	return e.keywordBlob
}

// ComputeHash generates an MD5 hash for deduplication based on key fields.
// Thread-safe and cached after first computation.
func (e *LogEvent) ComputeHash() string {
	e.hashMu.Lock()
	defer e.hashMu.Unlock()

	if e.hash != nil {
		return *e.hash
	}

	code := ""
	if e.EventCode != nil {
		code = strconv.Itoa(*e.EventCode)
	}
	keyFields := []string{
		e.getEventIDString(),
		code,
		e.GetStringField("process.name"),
		e.GetStringField("process.command_line"),
		e.GetStringField("CommandLine"),
		e.GetStringField("Image"),
		e.Timestamp.Format("2006-01-02 15:04"),
	}

	hashInput := strings.Join(keyFields, "|")
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashInput)))
	e.hash = &hash
	return hash
}

// String returns a human-readable string representation of the event.
func (e *LogEvent) String() string {
	eventIDStr := "N/A"
	if e.EventID != nil {
		eventIDStr = *e.EventID
	}
	return fmt.Sprintf("LogEvent{id=%s, category=%s, product=%s, timestamp=%s}",
		eventIDStr, e.Category, e.Product, e.Timestamp.Format(time.RFC3339))
}

// GetCategory returns the event category as a string.
// Implements ports.Event interface.
func (e *LogEvent) GetCategory() string {
	return string(e.Category)
}

// GetProduct returns the event product.
// Implements ports.Event interface.
func (e *LogEvent) GetProduct() string {
	return e.Product
}

// extractRecordID returns the event's record identity: the agent's top-level
// "event_id" (a UUID) or a standard record-id field. It deliberately reads the
// top level only — data.event_id carries a provider event code, not identity.
func (e *LogEvent) extractRecordID() *string {
	if v, ok := e.RawData["event_id"]; ok && v != nil {
		if s := strings.TrimSpace(ValueToString(v)); s != "" {
			return &s
		}
	}
	for _, path := range []string{"event.id", "EventRecordID", "winlog.record_id"} {
		if v := e.lookup(path); v != nil {
			if s := strings.TrimSpace(ValueToString(v)); s != "" {
				return &s
			}
		}
	}
	return nil
}

// extractEventCode returns the numeric provider event code (Sysmon/Windows
// Event Log), or nil when the event has none. Only numeric values are
// accepted, so a record UUID can never be mistaken for an event code.
func (e *LogEvent) extractEventCode() *int {
	candidates := []interface{}{
		e.lookup("event.code"),
		e.lookup("EventID"),
		e.lookup("winlog.event_id"),
		e.lookup("System.EventID"),
		e.lookup("Event.System.EventID"),
	}
	if data, ok := e.RawData["data"].(map[string]interface{}); ok {
		for _, k := range []string{"EventID", "event_id", "EventCode", "event_code", "winlog_event_id"} {
			candidates = append(candidates, data[k])
		}
	}
	for _, v := range candidates {
		if code, ok := ParseEventCode(v); ok {
			return &code
		}
	}
	return nil
}

// lookup returns a top-level value by exact key (including flattened dotted
// keys such as "event.code") or, failing that, by nested dot-path traversal.
// Unlike GetField it never falls back into the agent's data.* sub-map.
func (e *LogEvent) lookup(path string) interface{} {
	if v, ok := e.RawData[path]; ok && v != nil {
		return v
	}
	if strings.Contains(path, ".") {
		return e.getNested(path)
	}
	return nil
}

// ParseEventCode converts a provider event code to int. It accepts integer
// types, integral floats and decimal strings; anything else (e.g. a UUID)
// is rejected.
func ParseEventCode(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, t >= 0
	case int32:
		return int(t), t >= 0
	case int64:
		return int(t), t >= 0 && t <= 1<<31-1
	case uint32:
		return int(t), true
	case float64:
		if t >= 0 && t <= 1<<31-1 && t == float64(int64(t)) {
			return int(t), true
		}
	case json.Number:
		if n, err := strconv.Atoi(t.String()); err == nil && n >= 0 {
			return n, true
		}
	case string:
		s := strings.TrimSpace(t)
		if s == "" || len(s) > 10 {
			return 0, false
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return n, true
		}
	}
	return 0, false
}

// actionOf returns the lowercased agent "action" (top-level or data.action).
func (e *LogEvent) actionOf() string {
	if v, ok := e.GetField("action"); ok && v != nil {
		return strings.ToLower(strings.TrimSpace(ValueToString(v)))
	}
	return ""
}

func (e *LogEvent) inferCategory() EventCategory {
	// Check agent's event_type field first (our EDR agent sends this on every
	// event) and refine it with the agent's action so each event reaches the
	// specific Sigma category its rules are written for.
	if et, ok := e.GetField("event_type"); ok && et != nil {
		switch strings.ToLower(fmt.Sprintf("%v", et)) {
		case "process":
			switch e.actionOf() {
			case "process_termination":
				return EventCategoryProcessTermination
			case "snapshot", "inventory":
				// Start-up inventory of processes that were ALREADY running:
				// not a process creation. Evaluating it against
				// process_creation rules re-raised alerts for every running
				// process on each agent restart.
				return EventCategoryProcessInventory
			}
			return EventCategoryProcessCreation
		case "network":
			return EventCategoryNetworkConnection
		case "file":
			switch e.actionOf() {
			case "deleted", "delete":
				return EventCategoryFileDelete
			case "renamed", "rename":
				return EventCategoryFileRename
			default: // created / modified / unspecified
				return EventCategoryFileEvent
			}
		case "registry":
			switch e.actionOf() {
			case "value_set":
				return EventCategoryRegistrySet
			case "key_created":
				return EventCategoryRegistryAdd
			case "value_delete", "key_deleted":
				return EventCategoryRegistryDelete
			case "key_renamed", "renamed":
				return EventCategoryRegistryRename
			default:
				return EventCategoryRegistryEvent
			}
		case "vulnerability_finding", "software_inventory":
			// Inventory telemetry, not detection telemetry: no Sigma category.
			return EventCategoryUnknown
		case "dns":
			return EventCategoryDNSQuery
		case "auth":
			return EventCategoryAuthentication
		case "driver":
			return EventCategoryDriverLoad
		case "image_load":
			return EventCategoryImageLoad
		case "pipe":
			// Distinguish pipe_created vs pipe_connected from action field
			if act, aok := e.GetField("action"); aok {
				actStr := strings.ToLower(fmt.Sprintf("%v", act))
				if strings.Contains(actStr, "connect") {
					return EventCategoryPipeConnected
				}
			}
			return EventCategoryPipeCreated
		case "process_access":
			return EventCategoryProcessAccess
		case "wmi":
			return EventCategoryWMIEvent
		case "powershell":
			// Agent PowerShell telemetry from the Operational log.
			if e.actionOf() == "module" {
				return EventCategoryPsModule
			}
			return EventCategoryPsScript
		case "clipboard":
			// Clipboard telemetry is not file activity; evaluating it against
			// file_event rules would produce spurious matches.
			return EventCategoryClipboard
		}
	}

	if e.EventCode != nil {
		if cat := InferCategoryFromEventID(*e.EventCode); cat != EventCategoryUnknown {
			return cat
		}
	}

	if action, ok := e.GetField("event.action"); ok {
		actionStr := strings.ToLower(fmt.Sprintf("%v", action))
		if strings.Contains(actionStr, "start") || strings.Contains(actionStr, "create") || strings.Contains(actionStr, "exec") {
			return EventCategoryProcessCreation
		}
		if strings.Contains(actionStr, "connect") || strings.Contains(actionStr, "network") {
			return EventCategoryNetworkConnection
		}
		if strings.Contains(actionStr, "file") || strings.Contains(actionStr, "write") || strings.Contains(actionStr, "read") {
			return EventCategoryFileEvent
		}
		if strings.Contains(actionStr, "dns") || strings.Contains(actionStr, "query") {
			return EventCategoryDNSQuery
		}
		if strings.Contains(actionStr, "registry") {
			return EventCategoryRegistryEvent
		}
		if strings.Contains(actionStr, "logon") || strings.Contains(actionStr, "auth") || strings.Contains(actionStr, "login") {
			return EventCategoryAuthentication
		}
	}

	if category, ok := e.GetField("event.category"); ok {
		catStr := strings.ToLower(fmt.Sprintf("%v", category))
		if strings.Contains(catStr, "process") {
			return EventCategoryProcessCreation
		}
		if strings.Contains(catStr, "network") {
			return EventCategoryNetworkConnection
		}
		if strings.Contains(catStr, "file") {
			return EventCategoryFileEvent
		}
		if strings.Contains(catStr, "registry") {
			return EventCategoryRegistryEvent
		}
		if strings.Contains(catStr, "authentication") {
			return EventCategoryAuthentication
		}
	}

	if e.HasField("Image") || e.HasField("process.executable") {
		if e.HasField("CommandLine") || e.HasField("process.command_line") {
			return EventCategoryProcessCreation
		}
	}

	if e.HasField("DestinationIp") || e.HasField("destination.ip") {
		return EventCategoryNetworkConnection
	}

	if e.HasField("TargetFilename") || e.HasField("file.path") {
		return EventCategoryFileEvent
	}

	if e.HasField("TargetObject") || e.HasField("registry.path") {
		return EventCategoryRegistryEvent
	}

	if e.HasField("QueryName") || e.HasField("dns.question.name") {
		return EventCategoryDNSQuery
	}

	return EventCategoryUnknown
}

func (e *LogEvent) extractProduct() string {
	paths := []string{
		"source.os_type",
		"agent.type",
		"log.type",
		"winlog.provider_name",
		"event.module",
	}

	for _, path := range paths {
		if val, ok := e.GetField(path); ok && val != nil {
			valStr := strings.ToLower(fmt.Sprintf("%v", val))
			if strings.Contains(valStr, "windows") || strings.Contains(valStr, "sysmon") {
				return "windows"
			}
			if strings.Contains(valStr, "linux") {
				return "linux"
			}
			if strings.Contains(valStr, "macos") || strings.Contains(valStr, "darwin") {
				return "macos"
			}
		}
	}

	return "windows"
}

// sigmaServiceByChannel maps Windows Event Log channels to Sigma logsource
// service names (SigmaHQ taxonomy).
var sigmaServiceByChannel = map[string]string{
	"security":    "security",
	"system":      "system",
	"application": "application",
	"microsoft-windows-sysmon/operational":                     "sysmon",
	"microsoft-windows-powershell/operational":                 "powershell",
	"windows powershell":                                       "powershell-classic",
	"microsoft-windows-taskscheduler/operational":              "taskscheduler",
	"microsoft-windows-windows defender/operational":           "windefend",
	"microsoft-windows-wmi-activity/operational":               "wmi",
	"microsoft-windows-bits-client/operational":                "bits-client",
	"microsoft-windows-dns-client/operational":                 "dns-client",
	"microsoft-windows-codeintegrity/operational":              "codeintegrity-operational",
	"microsoft-windows-ntlm/operational":                       "ntlm",
	"microsoft-windows-driverframeworks-usermode/operational":  "driver-framework",
	"microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
	"microsoft-windows-printservice/admin":                     "printservice-admin",
	"microsoft-windows-printservice/operational":               "printservice-operational",
	"microsoft-windows-smbclient/security":                     "smbclient-security",
	"microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
	"microsoft-windows-appxdeploymentserver/operational":       "appxdeployment-server",
	"microsoft-windows-shell-core/operational":                 "shell-core",
	"microsoft-windows-openssh/operational":                    "openssh",
	"microsoft-windows-ldap-client/debug":                      "ldap",
}

// extractService derives the Sigma logsource service from the event's
// Windows Event Log channel, when present. Agent ETW telemetry carries no
// channel and therefore no service (it is routed by category instead).
func (e *LogEvent) extractService() string {
	candidates := []interface{}{
		e.lookup("winlog.channel"),
		e.lookup("Channel"),
		e.lookup("channel"),
		e.lookup("System.Channel"),
		e.lookup("Event.System.Channel"),
	}
	if data, ok := e.RawData["data"].(map[string]interface{}); ok {
		candidates = append(candidates, data["channel"], data["Channel"], data["log_name"])
	}
	for _, v := range candidates {
		ch := strings.ToLower(strings.TrimSpace(ValueToString(v)))
		if ch == "" {
			continue
		}
		if svc, ok := sigmaServiceByChannel[ch]; ok {
			return svc
		}
	}
	return ""
}

func (e *LogEvent) extractTimestamp() time.Time {
	paths := []string{
		"@timestamp",
		"timestamp",
		"event.created",
		"event.ingested",
		"EventTime",
		"UtcTime",
	}

	for _, path := range paths {
		if val, ok := e.GetField(path); ok && val != nil {
			switch v := val.(type) {
			case time.Time:
				return v
			case string:
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					return t
				}
				if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
					return t
				}
			}
		}
	}

	return time.Now()
}

func (e *LogEvent) getNested(path string) interface{} {
	if !strings.Contains(path, ".") {
		return nil
	}

	parts := strings.Split(path, ".")
	var current interface{} = e.RawData

	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}

		if val, exists := m[part]; exists {
			current = val
			continue
		}

		// Try case-insensitive match
		found := false
		for key, val := range m {
			if strings.EqualFold(key, part) {
				current = val
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	return current
}

func (e *LogEvent) getEventIDString() string {
	if e.EventID != nil {
		return *e.EventID
	}
	return ""
}
