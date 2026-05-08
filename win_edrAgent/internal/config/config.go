// Package config handles configuration loading and management for the EDR Agent.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v3"
)

// DefaultGRPCServerCertName is the DNS identity in the Connection Manager's
// TLS certificate (see connection-manager certgen). The agent often dials a
// different hostname (e.g. edr.local from the hosts file, or a public IP) but
// TLS verification must use this SNI, not the dial host, unless you deploy
// a certificate with matching SANs for that hostname.
const DefaultGRPCServerCertName = "edr-connection-manager"

// Config represents the complete agent configuration.
type Config struct {
	Server     ServerConfig    `yaml:"server"`
	Agent      AgentConfig     `yaml:"agent"`
	Collectors CollectorConfig `yaml:"collectors"`
	Filtering  FilteringConfig `yaml:"filtering"`
	Response   ResponseConfig  `yaml:"response"`
	Sysmon     SysmonConfig    `yaml:"sysmon"`
	Logging    LoggingConfig   `yaml:"logging"`
	Certs      CertConfig      `yaml:"certs"`
}

// SysmonConfig controls optional Sysmon bootstrap on Windows endpoints.
type SysmonConfig struct {
	// InstallOnFirstRun installs Sysmon (if missing) and enables the Operational channel.
	InstallOnFirstRun bool `yaml:"install_on_first_run"`
	// ConfigURL optionally points to a Sysmon XML config file to apply during install.
	ConfigURL string `yaml:"config_url"`
}

// ResponseConfig controls autonomous on-endpoint response (local hash DB, auto-quarantine).
type ResponseConfig struct {
	// AutoQuarantine enables hash lookup + quarantine on high-risk file paths (ETW file create/write).
	AutoQuarantine bool `yaml:"auto_quarantine"`
	// SignatureDBPath is the bbolt database path for malware_hashes (SHA-256 keys).
	// On startup the agent merges: (1) embedded builtin_hashes.ndjson (includes EICAR),
	// (2) optional NDJSON file "signature_seed.ndjson" in the same directory (operator-supplied hashes),
	// (3) hashes from C2 UPDATE_SIGNATURES. Large feeds should use UPDATE_SIGNATURES or the seed file.
	SignatureDBPath string `yaml:"signature_db_path"`
	// MaxScanBytes caps bytes read per file for hashing (0 = default 10 MiB).
	MaxScanBytes int64 `yaml:"max_scan_bytes"`
	// USBWatcher polls for removable volumes and registers them for auto-response paths.
	USBWatcher bool `yaml:"usb_watcher"`

	// SignatureAutoFetchEnabled periodically downloads a public MalwareBazaar CSV and merges new SHA-256 keys (no overwrite unless SignatureAutoFetchForce).
	// Host allowlist: bazaar.abuse.ch (HTTPS), or http://127.0.0.1 / localhost for testing.
	SignatureAutoFetchEnabled bool `yaml:"signature_auto_fetch_enabled"`
	// SignatureAutoFetchInterval between merges (default 24h).
	SignatureAutoFetchInterval time.Duration `yaml:"signature_auto_fetch_interval"`
	// SignatureAutoFetchURL defaults to MalwareBazaar recent CSV if empty.
	SignatureAutoFetchURL string `yaml:"signature_auto_fetch_url"`
	// SignatureAutoFetchLimit max hashes applied per run (default 500).
	SignatureAutoFetchLimit int `yaml:"signature_auto_fetch_limit"`
	// SignatureAutoFetchForce overwrites existing keys on each fetch (default false).
	SignatureAutoFetchForce bool `yaml:"signature_auto_fetch_force"`

	// SignatureServerSyncEnabled pulls delta NDJSON from the Connection Manager
	// instead of (or in addition to) the public MalwareBazaar feed.
	SignatureServerSyncEnabled bool `yaml:"signature_server_sync_enabled"`
	// SignatureServerSyncURL is the full URL to the server's NDJSON endpoint.
	// If empty it is auto-constructed from Server.Address.
	SignatureServerSyncURL string `yaml:"signature_server_sync_url"`
	// SignatureServerSyncInterval between server delta pulls (default 6h).
	SignatureServerSyncInterval time.Duration `yaml:"signature_server_sync_interval"`

	// ProcessAutoKillEnabled enables local process auto-response based on external rule packs.
	ProcessAutoKillEnabled bool `yaml:"process_auto_kill_enabled"`
	// ProcessRulesPath points to a JSON process response rules pack.
	ProcessRulesPath string `yaml:"process_rules_path"`
	// ProcessPreventionMode controls behavior on rule match ("detect_only" or "auto_kill_then_override").
	ProcessPreventionMode string `yaml:"process_prevention_mode"`
}

// ServerConfig defines Connection Manager connection settings.
type ServerConfig struct {
	Address           string        `yaml:"address"`
	Insecure          bool          `yaml:"insecure"` // if true, use plaintext gRPC (no TLS) for debugging / Host-VM connectivity
	Timeout           time.Duration `yaml:"timeout"`
	ReconnectDelay    time.Duration `yaml:"reconnect_delay"`
	MaxReconnectDelay time.Duration `yaml:"max_reconnect_delay"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// TLSServerName overrides the hostname used for TLS certificate SAN validation.
	// Use this when the server cert is issued for an internal service name
	// (e.g. "edr-connection-manager") but the agent connects via a custom deployment
	// domain (e.g. "edr.internal" or a raw IP). Leaving this empty uses the hostname
	// from Server.Address as-is.
	TLSServerName string `yaml:"tls_server_name"`
}

// AgentConfig defines agent behavior settings.
type AgentConfig struct {
	ID             string        `yaml:"id"`
	Hostname       string        `yaml:"hostname"`
	BatchSize      int           `yaml:"batch_size"`
	BatchInterval  time.Duration `yaml:"batch_interval"`
	BufferSize     int           `yaml:"buffer_size"`
	Compression    string        `yaml:"compression"`       // "snappy", "gzip", "none"
	QueueDir       string        `yaml:"queue_dir"`         // Offline disk queue directory (WAL)
	MaxQueueSizeMB int           `yaml:"max_queue_size_mb"` // Max disk queue size in MB
}

// CollectorConfig defines event collection settings.
type CollectorConfig struct {
	ETWEnabled       bool          `yaml:"etw_enabled"`
	ETWSessionName   string        `yaml:"etw_session_name"`
	WMIEnabled       bool          `yaml:"wmi_enabled"`
	WMIInterval      time.Duration `yaml:"wmi_interval"`
	RegistryEnabled  bool          `yaml:"registry_enabled"`
	FileEnabled      bool          `yaml:"file_enabled"`
	ImageLoadEnabled bool          `yaml:"imageload_enabled"`
	NetworkEnabled   bool          `yaml:"network_enabled"`

	// Phase 1 — New telemetry collectors (fill detection blind spots)
	DNSEnabled           bool `yaml:"dns_enabled"`            // ETW Microsoft-Windows-DNS-Client (enables 50+ Sigma dns_query rules)
	PipeEnabled          bool `yaml:"pipe_enabled"`           // Kernel FileIo pipe events (Cobalt Strike beacon pipe detection)
	ProcessAccessEnabled bool `yaml:"process_access_enabled"` // LSASS/credential dump detection (Mimikatz T1003.001)

	// Phase 2 — Vulnerability scanner integration (Trivy/Grype)
	VulnScanEnabled  bool          `yaml:"vuln_scan_enabled"`
	VulnScanInterval time.Duration `yaml:"vuln_scan_interval"`
	VulnScannerType  string        `yaml:"vuln_scanner_type"` // trivy | grype
	VulnScannerPath  string        `yaml:"vuln_scanner_path"` // optional absolute path to scanner binary
	VulnScanTimeout  time.Duration `yaml:"vuln_scan_timeout"`
	VulnScanArgs     []string      `yaml:"vuln_scan_args"` // optional override args
}

// FilteringConfig defines event filtering rules.
type FilteringConfig struct {
	ExcludeProcesses []string `yaml:"exclude_processes"`
	ExcludeIPs       []string `yaml:"exclude_ips"`
	ExcludeRegistry  []string `yaml:"exclude_registry"`
	ExcludePaths     []string `yaml:"exclude_paths"`
	IncludePaths     []string `yaml:"include_paths"`

	// Advanced filtering — Sysmon Event IDs to drop at the edge before serialization.
	// Common noisy IDs: 4 (Sysmon service state), 7 (ImageLoad), 15 (FileCreateStreamHash),
	// 22 (DNSEvent), 23 (FileDelete).
	ExcludeEventIDs []int `yaml:"exclude_event_ids"`

	// SHA256 hashes of known-good, trusted binaries whose events can be safely dropped.
	// Reduces noise from OS-native processes and verified third-party software.
	TrustedHashes []string `yaml:"trusted_hashes"`

	// FilterPrivateNetworks, when true, drops network connections where BOTH
	// source and destination are RFC 1918 private IPs (10.x, 172.16-31.x, 192.168.x).
	// This eliminates high-volume internal LAN noise with near-zero security signal.
	// Set to false to collect internal connections (e.g., lateral movement detection).
	FilterPrivateNetworks bool `yaml:"filter_private_networks"`

	// QoS rate limiting configuration for noisy event types.
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig defines per-event-type rate limiting using a Token Bucket algorithm.
type RateLimitConfig struct {
	// Enabled toggles rate limiting. When false, all events pass through unrestricted.
	Enabled bool `yaml:"enabled"`

	// DefaultMaxEPS is the default maximum Events Per Second for any event type
	// not explicitly listed in PerEventType. 0 means unlimited.
	DefaultMaxEPS int `yaml:"default_max_eps"`

	// CriticalBypass, when true, ensures events with Critical or High severity
	// are never rate-limited — they always pass through regardless of token state.
	CriticalBypass bool `yaml:"critical_bypass"`

	// PerEventType allows fine-grained EPS limits per event type.
	// Keys are event type strings: "dns", "network", "file", "image_load", etc.
	// Values are the max EPS allowed for that type.
	PerEventType map[string]int `yaml:"per_event_type"`
}

// LoggingConfig defines logging settings.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxAgeDays int    `yaml:"max_age_days"`
}

// CertConfig defines certificate paths and optional inline PEM data.
// When CertPEM/KeyPEM/CACertPEM are populated (from Registry), they take
// priority over file paths. This eliminates cert files from disk entirely.
type CertConfig struct {
	CertPath       string `yaml:"cert_path" json:"cert_path"`
	KeyPath        string `yaml:"key_path" json:"key_path"`
	CAPath         string `yaml:"ca_path" json:"ca_path"`
	BootstrapToken string `yaml:"bootstrap_token" json:"bootstrap_token"`

	// BuildID is the UUID baked into the binary at build time (EmbeddedBuildID).
	// Set in-memory by main.go before calling EnsureEnrolled.
	// Sent as req.Tags["build_id"] so agent_service.go can use the BuildID lookup path.
	// NEVER written to disk or Registry (yaml:"-", json:"-").
	BuildID string `yaml:"-" json:"-"`

	// Inline PEM data — stored in Registry, loaded into memory at startup.
	// When these are set, the file paths above are ignored for TLS.
	CertPEM   []byte `yaml:"-" json:"cert_pem,omitempty"`
	KeyPEM    []byte `yaml:"-" json:"key_pem,omitempty"`
	CACertPEM []byte `yaml:"-" json:"ca_cert_pem,omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	return &Config{
		Server: ServerConfig{
			Address:           "localhost:50051",
			Insecure:          false,
			Timeout:           30 * time.Second,
			ReconnectDelay:    1 * time.Second,
			MaxReconnectDelay: 30 * time.Second,
			HeartbeatInterval: 10 * time.Second,
			TLSServerName:     DefaultGRPCServerCertName,
		},
		Agent: AgentConfig{
			ID:             uuid.New().String(),
			Hostname:       hostname,
			BatchSize:      200,
			BatchInterval:  2 * time.Second,
			BufferSize:     5000,
			Compression:    "snappy",
			QueueDir:       "C:\\ProgramData\\EDR\\queue",
			MaxQueueSizeMB: 500,
		},
		Collectors: CollectorConfig{
			ETWEnabled:       true,
			ETWSessionName:   "EDRAgentSession",
			WMIEnabled:       true, // Matches config/default.yaml — periodic inventory + full telemetry for dashboard-built installs
			WMIInterval:      60 * time.Minute,
			RegistryEnabled:  true,
			FileEnabled:      true,
			ImageLoadEnabled: true,
			NetworkEnabled:   true,

			// Phase 1 — New collectors (enabled by default for full coverage)
			DNSEnabled:           true,
			PipeEnabled:          true,
			ProcessAccessEnabled: true,
			VulnScanEnabled:      true,
			VulnScanInterval:     6 * time.Hour,
			VulnScannerType:      "trivy",
			VulnScannerPath:      "",
			VulnScanTimeout:      20 * time.Minute,
			VulnScanArgs:         nil,
		},
		// Autonomous response defaults: used by installer.GenerateConfig (dashboard / zero-touch).
		// Keep aligned with config/default.yaml response.* so first-time installs are fully armed.
		Response: ResponseConfig{
			AutoQuarantine:            true,
			SignatureDBPath:           `C:\ProgramData\EDR\signatures.db`,
			MaxScanBytes:              10 << 20, // 10 MiB
			USBWatcher:                true,
			SignatureAutoFetchEnabled: false,
			SignatureAutoFetchInterval: 24 * time.Hour,
			SignatureAutoFetchURL:     "",
			SignatureAutoFetchLimit:   500,
			SignatureAutoFetchForce:   false,
			SignatureServerSyncEnabled:   false,
			SignatureServerSyncURL:       "",
			SignatureServerSyncInterval:  6 * time.Hour,
			ProcessAutoKillEnabled:    true,
			ProcessRulesPath:          `C:\ProgramData\EDR\process_prevention_rules.json`,
			ProcessPreventionMode:     "auto_kill_then_override",
		},
		Filtering: FilteringConfig{
			ExcludeProcesses: []string{
				// NOTE: svchost.exe is intentionally NOT excluded — it is a high-value
				// detection target (MITRE T1036.004 Masquerading). Malware frequently
				// masquerades as or is launched by svchost.

				// Core OS session managers — pure kernel infrastructure, zero attack surface
				"csrss.exe",
				"smss.exe",
				"wininit.exe",
				"winlogon.exe",
				"services.exe",
				"lsaiso.exe", // Credential Guard (isolated LSA)

				// Desktop / Shell infrastructure — noisy, not attack vectors
				"dwm.exe",
				"sihost.exe",
				"taskhostw.exe",
				"RuntimeBroker.exe",
				"ApplicationFrameHost.exe",
				"SystemSettings.exe",
				"TextInputHost.exe",
				"ctfmon.exe",
				"fontdrvhost.exe",
				"dashost.exe",

				// Audio / Media — no security signal
				"audiodg.exe",

				// Search indexing — extremely noisy
				"SearchIndexer.exe",
				"SearchProtocolHost.exe",
				"SearchFilterHost.exe",

				// Windows Update / Telemetry — periodic noise
				"wuauclt.exe",
				"musnotification.exe",
				"CompatTelRunner.exe",
				"MicrosoftEdgeUpdate.exe",

				// Security services (collecting their events is redundant)
				"MsMpEng.exe",
				"SecurityHealthService.exe",
				"SgrmBroker.exe",

				// COM infrastructure
				"dllhost.exe",

				// Print / background
				"spoolsv.exe",
				"backgroundTaskHost.exe",

				// Self — agent's own executable
				"edr-agent.exe",
				"agent.exe",
			},
			ExcludeIPs: []string{
				// Loopback / invalid
				"127.0.0.0/8",
				"::1/128",
				"0.0.0.0/32",
				// Link-local
				"169.254.0.0/16",
				"fe80::/10",
				// Multicast / broadcast
				"224.0.0.0/4",
				"255.255.255.255/32",
			},
			ExcludeRegistry: []string{
				"Component Based Servicing",
				"\\Services\\bam\\State",
				"\\Services\\WpnUserService",
				"\\DeviceAssociationService",
			},
			ExcludePaths: []string{
				"C:\\Windows\\Temp",
				"C:\\Users\\*\\AppData\\Local\\Temp",
				"C:\\Windows\\SoftwareDistribution",
				"C:\\Windows\\WinSxS",
				"C:\\Windows\\assembly",
				"C:\\Windows\\Installer",
				"C:\\Windows\\Microsoft.NET",
				"C:\\Windows\\servicing",
				"C:\\ProgramData\\Microsoft\\Windows Defender",
			},
			IncludePaths: []string{
				"C:\\Windows\\System32",
				"C:\\Program Files",
				"C:\\Program Files (x86)",
			},
			FilterPrivateNetworks: true, // Drop RFC 1918 private-to-private connections. Set to false for lateral movement detection.
			RateLimit: RateLimitConfig{
				Enabled:        true,
				DefaultMaxEPS:  500,
				CriticalBypass: true,
				PerEventType: map[string]int{
					"file":       200,
					"image_load": 100,
					"network":    50,
				},
			},
		},
		Logging: LoggingConfig{
			Level:      "INFO",
			FilePath:   "C:\\ProgramData\\EDR\\logs\\agent.log",
			MaxSizeMB:  100,
			MaxAgeDays: 7,
		},
		Certs: CertConfig{
			CertPath:       "C:\\ProgramData\\EDR\\client.crt",
			KeyPath:        "C:\\ProgramData\\EDR\\private.key",
			CAPath:         "C:\\ProgramData\\EDR\\ca-chain.crt",
			BootstrapToken: "",
		},
	}
}

// Load reads configuration from a YAML file.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults if file doesn't exist
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Address == "" {
		return fmt.Errorf("server.address is required")
	}
	if c.Agent.BatchSize < 1 || c.Agent.BatchSize > 10000 {
		return fmt.Errorf("agent.batch_size must be between 1 and 10000")
	}
	if c.Agent.BatchInterval < 100*time.Millisecond || c.Agent.BatchInterval > 60*time.Second {
		return fmt.Errorf("agent.batch_interval must be between 100ms and 60s")
	}
	if c.Agent.BufferSize < 100 || c.Agent.BufferSize > 100000 {
		return fmt.Errorf("agent.buffer_size must be between 100 and 100000")
	}
	if c.Agent.QueueDir == "" {
		c.Agent.QueueDir = "C:\\ProgramData\\EDR\\queue"
	}
	if c.Agent.MaxQueueSizeMB < 1 || c.Agent.MaxQueueSizeMB > 2000 {
		return fmt.Errorf("agent.max_queue_size_mb must be between 1 and 2000")
	}
	if c.Response.MaxScanBytes < 0 {
		return fmt.Errorf("response.max_scan_bytes cannot be negative")
	}
	if c.Response.SignatureDBPath == "" {
		c.Response.SignatureDBPath = `C:\ProgramData\EDR\signatures.db`
	}
	if c.Response.SignatureAutoFetchInterval <= 0 {
		c.Response.SignatureAutoFetchInterval = 24 * time.Hour
	}
	if c.Response.SignatureAutoFetchLimit <= 0 {
		c.Response.SignatureAutoFetchLimit = 500
	}
	if c.Response.SignatureServerSyncInterval <= 0 {
		c.Response.SignatureServerSyncInterval = 6 * time.Hour
	}
	if c.Response.ProcessRulesPath == "" {
		c.Response.ProcessRulesPath = `C:\ProgramData\EDR\process_prevention_rules.json`
	}
	if c.Response.ProcessPreventionMode == "" {
		c.Response.ProcessPreventionMode = "auto_kill_then_override"
	}
	switch c.Response.ProcessPreventionMode {
	case "auto_kill_then_override", "detect_only":
	default:
		return fmt.Errorf("response.process_prevention_mode must be detect_only or auto_kill_then_override")
	}
	if c.Collectors.VulnScanInterval <= 0 {
		c.Collectors.VulnScanInterval = 6 * time.Hour
	}
	if c.Collectors.VulnScanTimeout <= 0 {
		c.Collectors.VulnScanTimeout = 20 * time.Minute
	}
	if c.Collectors.VulnScannerType == "" {
		c.Collectors.VulnScannerType = "trivy"
	}
	switch strings.ToLower(c.Collectors.VulnScannerType) {
	case "trivy", "grype":
	default:
		return fmt.Errorf("collectors.vuln_scanner_type must be trivy or grype")
	}
	return nil
}

// DataDirectoriesToHarden lists NTFS paths that hold binaries, WAL, logs,
// quarantine, and encryption keys — used for SYSTEM-only ACLs while the agent runs.
func (c *Config) DataDirectoriesToHarden() []string {
	queue := c.Agent.QueueDir
	if queue == "" {
		queue = `C:\ProgramData\EDR\queue`
	}
	logPath := c.Logging.FilePath
	if logPath == "" {
		logPath = `C:\ProgramData\EDR\logs\agent.log`
	}
	logDir := filepath.Clean(filepath.Dir(logPath))
	if logDir == "" || logDir == "." {
		logDir = `C:\ProgramData\EDR\logs`
	}
	const (
		binDir = `C:\ProgramData\EDR\bin`
		qDir   = `C:\ProgramData\EDR\quarantine`
		encDir = `C:\ProgramData\EDR\EncryptKey`
	)
	sigPath := c.Response.SignatureDBPath
	if sigPath == "" {
		sigPath = `C:\ProgramData\EDR\signatures.db`
	}
	sigDir := filepath.Clean(filepath.Dir(sigPath))
	seen := make(map[string]struct{})
	out := make([]string, 0, 8)
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "." {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(binDir)
	add(queue)
	add(logDir)
	add(qDir)
	add(encDir)
	add(sigDir)
	return out
}

// Save writes configuration to a YAML file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Clone creates a deep copy of the configuration.
func (c *Config) Clone() *Config {
	clone := *c
	clone.Response = c.Response
	clone.Filtering.ExcludeProcesses = append([]string{}, c.Filtering.ExcludeProcesses...)
	clone.Filtering.ExcludeIPs = append([]string{}, c.Filtering.ExcludeIPs...)
	clone.Filtering.ExcludeRegistry = append([]string{}, c.Filtering.ExcludeRegistry...)
	clone.Filtering.ExcludePaths = append([]string{}, c.Filtering.ExcludePaths...)
	clone.Filtering.IncludePaths = append([]string{}, c.Filtering.IncludePaths...)
	clone.Filtering.ExcludeEventIDs = append([]int{}, c.Filtering.ExcludeEventIDs...)
	clone.Filtering.TrustedHashes = append([]string{}, c.Filtering.TrustedHashes...)
	if c.Filtering.RateLimit.PerEventType != nil {
		clone.Filtering.RateLimit.PerEventType = make(map[string]int, len(c.Filtering.RateLimit.PerEventType))
		for k, v := range c.Filtering.RateLimit.PerEventType {
			clone.Filtering.RateLimit.PerEventType[k] = v
		}
	}
	return &clone
}

// =========================================================================
// Registry-Based Configuration Storage
// =========================================================================
//
// These functions store the full agent config in the Windows Registry under:
//   HKLM\SOFTWARE\EDR\Agent\ConfigData  (REG_SZ, JSON-encoded)
//
// Benefits over config.yaml:
//   - Protected by DACL: only SYSTEM can read/write (after hardening)
//   - Owner set to SYSTEM: Administrators cannot change permissions
//   - Not visible as a plaintext file on disk
//   - Survives file system tampering
//
// The config.yaml file is used ONLY during initial installation, then
// migrated to Registry and deleted from disk.

const configRegistryPath = `SOFTWARE\EDR\Agent`

// SaveToRegistry serializes the entire configuration as JSON and stores it
// in a protected registry key. The caller is responsible for clearing
// sensitive fields (e.g., BootstrapToken) before calling this function.
//
// During install: called WITH token (for first-boot enrollment).
// After enrollment: called WITHOUT token (enrollment code wipes it first).
func (c *Config) SaveToRegistry() error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal for registry: %w", err)
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, configRegistryPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("config: create registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue("ConfigData", string(data)); err != nil {
		return fmt.Errorf("config: write config to registry: %w", err)
	}
	return nil
}

// LoadFromRegistry attempts to load the full configuration from the protected
// registry key. Returns nil, nil if no config is stored (not an error — caller
// should fall back to YAML or defaults).
func LoadFromRegistry() (*Config, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, configRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil // Key doesn't exist — first boot / fresh install
	}
	defer k.Close()

	raw, _, err := k.GetStringValue("ConfigData")
	if err != nil || raw == "" {
		return nil, nil // No config stored yet
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal registry config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: invalid registry config: %w", err)
	}

	return cfg, nil
}

// DeleteConfigFile removes the plaintext config.yaml from disk.
// Called after the config has been successfully migrated to Registry.
// This is a one-way migration — the YAML file is no longer needed.
func DeleteConfigFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config: delete yaml file: %w", err)
	}
	return nil
}

// UnmarshalJSON deserializes a JSON-encoded config into the given struct.
// Used by the config sync pipeline when the server pushes a new config
// via gRPC HeartbeatResponse.new_config.
func UnmarshalJSON(data []byte, cfg *Config) error {
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("config: unmarshal JSON: %w", err)
	}
	return nil
}
