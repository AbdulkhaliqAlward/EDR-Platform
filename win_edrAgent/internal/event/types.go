// Package event provides event types and processing for the EDR Agent.
package event

import (
	"time"

	"github.com/google/uuid"
)

// EventType identifies the type of security event.
type EventType string

const (
	EventTypeProcess   EventType = "process"
	EventTypeNetwork   EventType = "network"
	EventTypeFile      EventType = "file"
	EventTypeRegistry  EventType = "registry"
	EventTypeDNS       EventType = "dns"
	EventTypeAuth      EventType = "auth"
	EventTypeDriver    EventType = "driver"
	EventTypeImageLoad EventType = "image_load"
	EventTypePipe          EventType = "pipe"
	EventTypeProcessAccess EventType = "process_access"
	EventTypeWMI           EventType = "wmi"
	EventTypePowerShell    EventType = "powershell" // Script Block / Module logging (Microsoft-Windows-PowerShell/Operational)
	EventTypeClipboard     EventType = "clipboard"
	EventTypeVulnerability EventType = "vulnerability_finding"
	EventTypeSoftwareInventory EventType = "software_inventory"
)

// Severity represents event severity level.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON serializes Severity as a JSON string (e.g., "low", "high")
// instead of a number. This ensures compatibility with the Connection Manager's
// JSON schema validator which expects severity to be a string.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Event represents a security event collected by the agent.
type Event struct {
	ID        string                 `json:"event_id"`
	Type      EventType              `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  Severity               `json:"severity"`
	Source    EventSource            `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Raw       string                 `json:"raw,omitempty"`
}

// EventSource identifies the origin of an event.
type EventSource struct {
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// NewEvent creates a new event with a generated ID.
func NewEvent(eventType EventType, severity Severity, data map[string]interface{}) *Event {
	return &Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Severity:  severity,
		Data:      data,
	}
}

// ProcessEvent represents a process creation/termination event.
type ProcessEvent struct {
	Action            string `json:"action"` // "created", "terminated"
	PID               int64  `json:"pid"`
	PPID              int64  `json:"ppid"`
	Name              string `json:"name"`
	Executable        string `json:"executable"`
	CommandLine       string `json:"command_line"`
	WorkingDirectory  string `json:"working_directory"`
	HashSHA256        string `json:"hash_sha256,omitempty"`
	HashMD5           string `json:"hash_md5,omitempty"`
	UserName          string `json:"user_name"`
	UserDomain        string `json:"user_domain"`
	UserSID           string `json:"user_sid,omitempty"`
	ParentName        string `json:"parent_name,omitempty"`
	ParentExecutable  string `json:"parent_executable,omitempty"`
	ParentCommandLine string `json:"parent_command_line,omitempty"`
	IntegrityLevel    string `json:"integrity_level,omitempty"`
	IsElevated        bool   `json:"is_elevated"`
	SignatureStatus   string `json:"signature_status,omitempty"`
	SignatureIssuer   string `json:"signature_issuer,omitempty"`
}

// NetworkEvent represents a network connection event.
type NetworkEvent struct {
	Action              string `json:"action"`    // "connection_attempted", "connection_established", "listening"
	Direction           string `json:"direction"` // "inbound", "outbound"
	Protocol            string `json:"protocol"`  // "tcp", "udp", "icmp"
	SourceIP            string `json:"source_ip"`
	SourcePort          int    `json:"source_port"`
	DestinationIP       string `json:"destination_ip"`
	DestinationPort     int    `json:"destination_port"`
	DestinationHostname string `json:"destination_hostname,omitempty"`
	PID                 int64  `json:"pid"`
	ProcessName         string `json:"process_name"`
	BytesSent           int64  `json:"bytes_sent,omitempty"`
	BytesReceived       int64  `json:"bytes_received,omitempty"`
}

// FileEvent represents a file operation event.
type FileEvent struct {
	Action       string    `json:"action"` // "created", "modified", "deleted", "renamed", "accessed"
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Extension    string    `json:"extension,omitempty"`
	Directory    string    `json:"directory"`
	SizeBytes    int64     `json:"size_bytes,omitempty"`
	HashSHA256   string    `json:"hash_sha256,omitempty"`
	PreviousPath string    `json:"previous_path,omitempty"`
	NewPath      string    `json:"new_path,omitempty"`
	PID          int64     `json:"pid"`
	ProcessName  string    `json:"process_name"`
	CreatedTime  time.Time `json:"created_time,omitempty"`
	ModifiedTime time.Time `json:"modified_time,omitempty"`
}

// RegistryEvent represents a Windows Registry operation event.
type RegistryEvent struct {
	Action       string `json:"action"` // "created", "modified", "deleted", "queried"
	KeyPath      string `json:"key_path"`
	ValueName    string `json:"value_name,omitempty"`
	ValueType    string `json:"value_type,omitempty"` // "REG_SZ", "REG_DWORD", etc.
	ValueData    string `json:"value_data,omitempty"`
	PreviousData string `json:"previous_data,omitempty"`
	PID          int64  `json:"pid"`
	ProcessName  string `json:"process_name"`
}

// DNSEvent represents a DNS query event.
type DNSEvent struct {
	Action       string   `json:"action"` // "query", "response"
	QueryName    string   `json:"query_name"`
	QueryType    string   `json:"query_type"` // "A", "AAAA", "CNAME", "MX", etc.
	Answers      []string `json:"answers,omitempty"`
	ResponseCode string   `json:"response_code,omitempty"` // "NOERROR", "NXDOMAIN", etc.
	PID          int64    `json:"pid"`
	ProcessName  string   `json:"process_name"`
}

// AuthEvent represents an authentication event.
type AuthEvent struct {
	Action         string `json:"action"`    // "login", "logout", "failed_login"
	AuthType       string `json:"auth_type"` // "interactive", "network", "service", "batch"
	UserName       string `json:"user_name"`
	UserDomain     string `json:"user_domain"`
	UserSID        string `json:"user_sid,omitempty"`
	SourceIP       string `json:"source_ip,omitempty"`
	SourceHostname string `json:"source_hostname,omitempty"`
	LogonID        string `json:"logon_id,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
	FailureCode    int    `json:"failure_code,omitempty"`
}

// DriverEvent represents a driver load/unload event.
type DriverEvent struct {
	Action          string `json:"action"` // "loaded", "unloaded"
	Name            string `json:"name"`
	Path            string `json:"path"`
	HashSHA256      string `json:"hash_sha256,omitempty"`
	SignatureStatus string `json:"signature_status,omitempty"`
	SignatureIssuer string `json:"signature_issuer,omitempty"`
}

// ImageLoadEvent represents a DLL/module loading event.
type ImageLoadEvent struct {
	Action          string `json:"action"` // "loaded"
	Path            string `json:"path"`
	Name            string `json:"name"`
	HashSHA256      string `json:"hash_sha256,omitempty"`
	PID             int64  `json:"pid"`
	ProcessName     string `json:"process_name"`
	SignatureStatus string `json:"signature_status,omitempty"`
	IsSigned        bool   `json:"is_signed"`
}

// PipeEvent represents a named pipe operation event.
type PipeEvent struct {
	Action      string `json:"action"` // "created", "connected"
	PipeName    string `json:"pipe_name"`
	PID         int64  `json:"pid"`
	ProcessName string `json:"process_name"`
	ProcessPath string `json:"process_path,omitempty"`
}

// ProcessAccessEvent represents a handle-open-to-sensitive-process event.
// Detects credential dumping (Mimikatz T1003.001), process injection (T1055),
// and other cross-process manipulation attempts.
type ProcessAccessEvent struct {
	Action            string `json:"action"`              // "open_process"
	SourcePID         int64  `json:"source_pid"`
	SourceProcessName string `json:"source_process_name"`
	SourceProcessPath string `json:"source_process_path,omitempty"`
	TargetPID         int64  `json:"target_pid"`
	TargetProcessName string `json:"target_process_name"`
	TargetProcessPath string `json:"target_process_path,omitempty"`
	AccessMask        string `json:"access_mask"`        // hex string e.g. "0x1F0FFF"
	AccessMaskInt     uint32 `json:"access_mask_int"`
	UserSID           string `json:"user_sid,omitempty"`
	UserName          string `json:"user_name,omitempty"`
}

// WMIEvent represents a WMI operation event.
type WMIEvent struct {
	Action      string `json:"action"` // "query", "consumer_created", "subscription_created"
	Namespace   string `json:"namespace"`
	Query       string `json:"query,omitempty"`
	Consumer    string `json:"consumer,omitempty"`
	Filter      string `json:"filter,omitempty"`
	PID         int64  `json:"pid"`
	ProcessName string `json:"process_name"`
}

// ClipboardEvent represents a clipboard access event.
type ClipboardEvent struct {
	Action      string `json:"action"` // "accessed", "modified"
	PID         int64  `json:"pid"`
	ProcessName string `json:"process_name"`
	ContentType string `json:"content_type,omitempty"`
	ContentSize int    `json:"content_size,omitempty"`
}
