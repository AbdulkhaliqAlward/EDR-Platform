package mapping

import (
	"fmt"
	"strings"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
)

// FieldType represents the data type of a field.
type FieldType string

const (
	FieldTypeString FieldType = "string"
	FieldTypeInt    FieldType = "int"
	FieldTypeFloat  FieldType = "float"
	FieldTypeBool   FieldType = "bool"
	FieldTypeArray  FieldType = "array"
	FieldTypeObject FieldType = "object"
)

// FieldMapping represents a field mapping between ECS and Sigma formats.
type FieldMapping struct {
	SigmaName    string
	ECSName      string
	Alternatives []string
	DataType     FieldType
	NestedPath   bool
}

// FieldMapper provides bidirectional field mapping between ECS, Sigma, and Sysmon formats.
// Thread-safe and optimized for high-performance field resolution.
type FieldMapper struct {
	ecsToSigma           map[string]*FieldMapping
	sigmaToAgentFallback map[string][]string // fallback chains for agent data.*
	sigmaToECS           map[string]*FieldMapping
	alternatives         map[string]*FieldMapping
	sigmaToAgentData     map[string]string // Sigma/ECS field -> agent data.* path
	fieldCache           *cache.FieldResolutionCache
}

// NewFieldMapper creates a new field mapper with all built-in mappings.
func NewFieldMapper(fieldCache *cache.FieldResolutionCache) *FieldMapper {
	fm := &FieldMapper{
		ecsToSigma:           make(map[string]*FieldMapping),
		sigmaToAgentFallback: make(map[string][]string),
		sigmaToECS:           make(map[string]*FieldMapping),
		alternatives:         make(map[string]*FieldMapping),
		sigmaToAgentData:     make(map[string]string),
		fieldCache:           fieldCache,
	}

	fm.initializeMappings()
	fm.initializeAgentMappings()
	return fm
}

// initializeMappings initializes all field mappings.
func (fm *FieldMapper) initializeMappings() {
	mappings := []*FieldMapping{
		// Process fields
		{"Image", "process.name", []string{"process.executable", "TargetImage", "SourceImage", "NewProcessName"}, FieldTypeString, false},
		{"CommandLine", "process.command_line", []string{"process.args", "ProcessCommandLine", "Command"}, FieldTypeString, false},
		{"ProcessId", "process.pid", []string{"process.entity_id"}, FieldTypeInt, false},
		{"ProcessGuid", "process.entity_id", []string{}, FieldTypeString, false},
		{"CurrentDirectory", "process.working_directory", []string{}, FieldTypeString, false},
		{"ParentImage", "process.parent.name", []string{"process.parent.executable", "ParentProcessName", "CallerProcessName"}, FieldTypeString, false},
		{"ParentCommandLine", "process.parent.command_line", []string{"ParentProcessCommandLine"}, FieldTypeString, false},
		{"ParentProcessId", "process.parent.pid", []string{}, FieldTypeInt, false},
		{"ParentProcessGuid", "process.parent.entity_id", []string{}, FieldTypeString, false},
		{"Hashes", "process.hash.md5", []string{"process.hash.sha1", "process.hash.sha256", "file.hash.md5", "file.hash.sha1", "file.hash.sha256"}, FieldTypeString, false},
		{"Company", "process.pe.company", []string{"file.pe.company"}, FieldTypeString, false},
		{"Description", "process.pe.description", []string{"file.pe.description"}, FieldTypeString, false},
		{"FileVersion", "process.pe.file_version", []string{}, FieldTypeString, false},
		{"Product", "process.pe.product", []string{}, FieldTypeString, false},
		{"OriginalFileName", "process.pe.original_file_name", []string{"file.pe.original_file_name"}, FieldTypeString, false},
		{"Imphash", "process.pe.imphash", []string{}, FieldTypeString, false},

		// User fields
		{"User", "user.name", []string{"UserName", "SubjectUserName", "AccountName"}, FieldTypeString, false},
		{"LogonDomain", "user.domain", []string{}, FieldTypeString, false},
		{"LogonId", "user.id", []string{}, FieldTypeString, false},
		{"TargetUserName", "user.target.name", []string{}, FieldTypeString, false},
		{"TargetDomainName", "user.target.domain", []string{}, FieldTypeString, false},

		// Network fields
		{"DestinationIp", "destination.ip", []string{"DestinationHostname"}, FieldTypeString, false},
		{"DestinationPort", "destination.port", []string{}, FieldTypeInt, false},
		{"DestinationHostname", "destination.domain", []string{}, FieldTypeString, false},
		{"SourceIp", "source.ip", []string{}, FieldTypeString, false},
		{"SourcePort", "source.port", []string{}, FieldTypeInt, false},
		{"Protocol", "network.protocol", []string{}, FieldTypeString, false},
		{"Initiated", "network.direction", []string{}, FieldTypeString, false},
		{"QueryName", "dns.question.name", []string{}, FieldTypeString, false},
		{"QueryResults", "dns.answers.data", []string{}, FieldTypeString, false},

		// File fields
		{"TargetFilename", "file.path", []string{"file.name", "file.directory", "file.extension", "TargetFileName", "FileName", "FilePath"}, FieldTypeString, false},
		{"ImageLoaded", "dll.path", []string{"dll.name"}, FieldTypeString, false},
		{"PipeName", "file.pipe.name", []string{}, FieldTypeString, false},

		// Process Access fields (Sysmon EventID 10 equivalent)
		{"SourceImage", "process.source.executable", []string{"source_process_path"}, FieldTypeString, false},
		{"TargetImage", "process.target.executable", []string{"target_process_path"}, FieldTypeString, false},
		{"GrantedAccess", "process.access.mask", []string{"access_mask"}, FieldTypeString, false},
		{"SourceProcessId", "process.source.pid", []string{"source_pid"}, FieldTypeInt, false},
		{"TargetProcessId", "process.target.pid", []string{"target_pid"}, FieldTypeInt, false},
		{"CallTrace", "process.access.call_trace", []string{}, FieldTypeString, false},

		// Extended DNS fields
		{"QueryType", "dns.question.type", []string{"query_type"}, FieldTypeString, false},
		{"QueryStatus", "dns.response_code", []string{"query_status"}, FieldTypeString, false},

		// Registry fields
		{"TargetObject", "registry.path", []string{"registry.key", "ObjectName", "RegistryKey"}, FieldTypeString, true},
		{"Details", "registry.value", []string{"registry.data.strings"}, FieldTypeString, false},

		// Event metadata
		// NOTE: the agent's top-level "event_id" is the event's record UUID,
		// not a provider event code, so it must never be an EventID
		// alternative. Agent-side codes live under data.* (see fallbacks).
		{"EventID", "event.code", []string{"EventCode", "winlog.event_id"}, FieldTypeInt, false},
		{"Provider_Name", "event.provider", []string{"winlog.provider_name"}, FieldTypeString, false},
		{"EventType", "event.action", []string{"event.type"}, FieldTypeString, false},
		{"Category", "event.category", []string{}, FieldTypeString, false},

		// Host fields
		{"ComputerName", "host.name", []string{"host.hostname"}, FieldTypeString, false},

		// Service fields
		{"ServiceName", "service.name", []string{}, FieldTypeString, false},
		{"Channel", "winlog.channel", []string{}, FieldTypeString, false},
	}

	// Build lookup maps
	for _, mapping := range mappings {
		// ECS to Sigma
		fm.ecsToSigma[mapping.ECSName] = mapping

		// Sigma to ECS
		fm.sigmaToECS[mapping.SigmaName] = mapping

		// Alternatives
		for _, alt := range mapping.Alternatives {
			fm.alternatives[strings.ToLower(alt)] = mapping
		}
	}
}

// initializeAgentMappings maps Sigma/Sysmon field names to the EDR agent's
// data.* namespace so the detection engine can resolve fields from agent telemetry.
func (fm *FieldMapper) initializeAgentMappings() {
	agentMap := map[string]string{
		// Process fields
		"Image":             "data.executable",
		"CommandLine":       "data.command_line",
		"ParentImage":       "data.parent_executable",
		"ParentCommandLine": "data.parent_command_line",
		"ProcessId":         "data.pid",
		"ParentProcessId":   "data.ppid",
		"User":              "data.user_name",
		"CurrentDirectory":  "data.working_directory",
		"Hashes":            "data.hashes",
		"OriginalFileName":  "data.original_file_name",
		"IntegrityLevel":    "data.integrity_level",
		"Company":           "data.company",
		"Description":       "data.description",
		"Product":           "data.product",

		// Network fields
		"DestinationIp":       "data.destination_ip",
		"DestinationPort":     "data.destination_port",
		"DestinationHostname": "data.destination_hostname",
		"SourceIp":            "data.source_ip",
		"SourcePort":          "data.source_port",
		"Protocol":            "data.protocol",

		// DNS fields
		"QueryName":    "data.query_name",
		"QueryResults": "data.query_results",

		// File fields
		"TargetFilename": "data.target_filename",
		"ImageLoaded":    "data.image_loaded",

		// Registry fields
		"TargetObject": "data.target_object",
		"Details":      "data.details",
		"EventType":    "data.EventType",

		// Pipe fields
		"PipeName": "data.pipe_name",

		// PowerShell Script Block Logging (Sigma ps_script, EventID 4104) and
		// Module Logging (ps_module, EventID 4103)
		"ScriptBlockText": "data.script_block_text",
		"ScriptBlockId":   "data.script_block_id",
		"Path":            "data.script_path",
		"MessageNumber":   "data.message_number",
		"MessageTotal":    "data.message_total",
		"Payload":         "data.payload",
		"ContextInfo":     "data.context_info",

		// Process Access fields (Sigma process_access / Sysmon EventID 10)
		"SourceImage":     "data.source_process_path",
		"TargetImage":     "data.target_process_path",
		"GrantedAccess":   "data.access_mask",
		"SourceProcessId": "data.source_pid",
		"TargetProcessId": "data.target_pid",
		"CallTrace":       "data.call_trace",

		// Extended DNS fields
		"QueryType":   "data.query_type",
		"QueryStatus": "data.QueryStatus",

		// Driver/Image load fields
		"ImagePath":  "data.image_path",
		"SignedBy":   "data.signed_by",
		"Signature":  "data.signature",
		"DriverName": "data.driver_name",

		// Auth fields
		"LogonType":        "data.logon_type",
		"TargetUserName":   "data.target_user_name",
		"TargetDomainName": "data.target_domain_name",
		"SubjectUserName":  "data.subject_user_name",

		// Host fields
		"ComputerName": "source.hostname",

		// Service fields
		"ServiceName": "data.service_name",

		// Event metadata — CRITICAL: EventID is emitted as a string by the
		// Windows ETW/Sysmon collector ("event_id": "4688"). Without this
		// mapping every EventID-gated Sigma rule silently fails to fire.
		"EventID":       "data.event_id",
		"Channel":       "data.channel",
		"Provider_Name": "data.provider_name",
	}

	for sigma, agentPath := range agentMap {
		fm.sigmaToAgentData[sigma] = agentPath
		fm.sigmaToAgentData[strings.ToLower(sigma)] = agentPath
	}

	// Also map ECS-style names to agent paths
	ecsAgentMap := map[string]string{
		"process.executable":          "data.executable",
		"process.name":                "data.name",
		"process.command_line":        "data.command_line",
		"process.pid":                 "data.pid",
		"process.working_directory":   "data.working_directory",
		"process.parent.name":         "data.parent_name",
		"process.parent.executable":   "data.parent_executable",
		"process.parent.command_line": "data.parent_command_line",
		"process.parent.pid":          "data.ppid",
		"process.hash.md5":            "data.hashes",
		"process.hash.sha256":         "data.hashes",
		"destination.ip":              "data.destination_ip",
		"destination.port":            "data.destination_port",
		"destination.domain":          "data.destination_hostname",
		"source.ip":                   "data.source_ip",
		"source.port":                 "data.source_port",
		"network.protocol":            "data.protocol",
		"dns.question.name":           "data.query_name",
		"file.path":                   "data.target_filename",
		"file.name":                   "data.target_filename",
		"dll.path":                    "data.image_loaded",
		"registry.path":               "data.target_object",
		"registry.value":              "data.details",
		"user.name":                   "data.user_name",
		"host.name":                   "source.hostname",
		"host.hostname":               "source.hostname",
	}

	for ecs, agentPath := range ecsAgentMap {
		fm.sigmaToAgentData[ecs] = agentPath
	}

	// Fallback chains: when primary agent path is empty/nil, try these secondaries
	// This is critical for snapshot-mode events that may have 'name' but not 'executable'
	// Image should represent process image path/name, not arbitrary file/module names.
	// For file/network/dns collectors, process_path is the closest equivalent.
	fm.sigmaToAgentFallback["Image"] = []string{"data.executable", "data.process_path", "data.image_path", "data.process_name"}
	fm.sigmaToAgentFallback["image"] = []string{"data.executable", "data.process_path", "data.image_path", "data.process_name"}
	// CommandLine must be resolved from real command-line fields only.
	// Falling back to executable/module names causes incorrect matches.
	fm.sigmaToAgentFallback["CommandLine"] = []string{"data.command_line", "data.CommandLine"}
	fm.sigmaToAgentFallback["commandline"] = []string{"data.command_line", "data.CommandLine"}
	fm.sigmaToAgentFallback["ParentImage"] = []string{"data.parent_executable", "data.parent_name"}
	fm.sigmaToAgentFallback["parentimage"] = []string{"data.parent_executable", "data.parent_name"}
	fm.sigmaToAgentFallback["ParentCommandLine"] = []string{"data.parent_command_line", "data.ParentCommandLine"}
	fm.sigmaToAgentFallback["parentcommandline"] = []string{"data.parent_command_line", "data.ParentCommandLine"}
	fm.sigmaToAgentFallback["User"] = []string{"data.user_name", "data.user", "data.user_sid"}
	fm.sigmaToAgentFallback["user"] = []string{"data.user_name", "data.user", "data.user_sid"}

	// Registry fallbacks
	fm.sigmaToAgentFallback["TargetObject"] = []string{"data.TargetObject", "data.target_object", "data.key_path"}
	fm.sigmaToAgentFallback["targetobject"] = []string{"data.TargetObject", "data.target_object", "data.key_path"}
	fm.sigmaToAgentFallback["Details"] = []string{"data.Details", "data.details", "data.value_data"}
	fm.sigmaToAgentFallback["details"] = []string{"data.Details", "data.details", "data.value_data"}

	// DNS fallbacks
	fm.sigmaToAgentFallback["QueryName"] = []string{"data.QueryName", "data.query_name"}
	fm.sigmaToAgentFallback["queryname"] = []string{"data.QueryName", "data.query_name"}

	// Process Access fallbacks
	fm.sigmaToAgentFallback["SourceImage"] = []string{"data.SourceImage", "data.source_process_path"}
	fm.sigmaToAgentFallback["sourceimage"] = []string{"data.SourceImage", "data.source_process_path"}
	fm.sigmaToAgentFallback["TargetImage"] = []string{"data.TargetImage", "data.target_process_path"}
	fm.sigmaToAgentFallback["targetimage"] = []string{"data.TargetImage", "data.target_process_path"}
	fm.sigmaToAgentFallback["GrantedAccess"] = []string{"data.GrantedAccess", "data.access_mask"}
	fm.sigmaToAgentFallback["grantedaccess"] = []string{"data.GrantedAccess", "data.access_mask"}

	// Pipe fallbacks
	fm.sigmaToAgentFallback["PipeName"] = []string{"data.PipeName", "data.pipe_name"}
	fm.sigmaToAgentFallback["pipename"] = []string{"data.PipeName", "data.pipe_name"}

	// EventID fallbacks — agent may emit as "EventID", "event_id", "EventCode", or "winlog.event_id"
	fm.sigmaToAgentFallback["EventID"] = []string{"data.event_id", "data.EventID", "data.EventCode", "data.winlog_event_id"}
	fm.sigmaToAgentFallback["eventid"] = []string{"data.event_id", "data.EventID", "data.EventCode", "data.winlog_event_id"}

	// Network fallbacks (new collector emits both Sigma and agent-style names)
	fm.sigmaToAgentFallback["DestinationIp"] = []string{"data.DestinationIp", "data.destination_ip"}
	fm.sigmaToAgentFallback["destinationip"] = []string{"data.DestinationIp", "data.destination_ip"}
	fm.sigmaToAgentFallback["SourceIp"] = []string{"data.SourceIp", "data.source_ip"}
	fm.sigmaToAgentFallback["sourceip"] = []string{"data.SourceIp", "data.source_ip"}

	// File collector fallbacks
	fm.sigmaToAgentFallback["TargetFilename"] = []string{"data.target_filename", "data.path", "data.name"}
	fm.sigmaToAgentFallback["targetfilename"] = []string{"data.target_filename", "data.path", "data.name"}
}

// ECSToSigma maps an ECS field name to Sigma field name.
func (fm *FieldMapper) ECSToSigma(ecsField string) (string, bool) {
	if mapping, ok := fm.ecsToSigma[ecsField]; ok {
		return mapping.SigmaName, true
	}
	return "", false
}

// SigmaToECS maps a Sigma field name to ECS field name.
func (fm *FieldMapper) SigmaToECS(sigmaField string) (string, bool) {
	// Try direct mapping
	if mapping, ok := fm.sigmaToECS[sigmaField]; ok {
		return mapping.ECSName, true
	}

	// Try case-insensitive lookup
	fieldLower := strings.ToLower(sigmaField)
	for sigma, mapping := range fm.sigmaToECS {
		if strings.ToLower(sigma) == fieldLower {
			return mapping.ECSName, true
		}
	}

	// Try alternatives
	if mapping, ok := fm.alternatives[fieldLower]; ok {
		return mapping.ECSName, true
	}

	return "", false
}

// ResolveField resolves a field value from event data using field mapping.
// Supports nested field paths and caching for performance.
func (fm *FieldMapper) ResolveField(eventData map[string]interface{}, fieldName string) (interface{}, FieldType, error) {
	if eventData == nil {
		return nil, FieldTypeString, fmt.Errorf("eventData cannot be nil")
	}

	// IMPORTANT (production correctness):
	// Do NOT cache resolved *values* here. This method is called per-event, and caching by
	// field name alone would mix values across different events, causing catastrophic
	// false positives / false negatives.
	//
	// Value-level caching (if desired) must be keyed by event identity (see SelectionEvaluator,
	// which uses event.ComputeHash()).

	// Values are already decoded at ingestion. Preserve literal backslashes in
	// UNC/device paths, regular expressions and script source; decoding twice
	// corrupts evidence and changes detection semantics.

	// 1) Direct field access
	if val, ok := eventData[fieldName]; ok {
		return val, FieldTypeString, nil
	}

	// 2) Nested field access (dot notation)
	if val := fm.getNested(eventData, fieldName); val != nil {
		return val, FieldTypeString, nil
	}

	// 3) ECS mapping (Sigma -> ECS)
	if ecsField, ok := fm.SigmaToECS(fieldName); ok {
		if val := fm.getNested(eventData, ecsField); val != nil {
			return val, FieldTypeString, nil
		}
	}

	// 4) Alternative fields (Sigma mapping alternatives)
	if mapping, ok := fm.sigmaToECS[fieldName]; ok {
		for _, alt := range mapping.Alternatives {
			// Try direct
			if val, ok := eventData[alt]; ok {
				return val, mapping.DataType, nil
			}
			// Try nested
			if val := fm.getNested(eventData, alt); val != nil {
				return val, mapping.DataType, nil
			}
		}
	}

	// 5) EDR Agent data.* namespace resolution
	if agentPath, ok := fm.sigmaToAgentData[fieldName]; ok {
		if val := fm.getNested(eventData, agentPath); val != nil {
			return val, FieldTypeString, nil
		}
	}
	if agentPath, ok := fm.sigmaToAgentData[strings.ToLower(fieldName)]; ok {
		if val := fm.getNested(eventData, agentPath); val != nil {
			return val, FieldTypeString, nil
		}
	}

	// 5b) EDR Agent fallback chain (e.g. Image: try data.executable, then data.name)
	if chain, ok := fm.sigmaToAgentFallback[fieldName]; ok {
		for _, path := range chain {
			if val := fm.getNested(eventData, path); val != nil {
				// For string values, skip empty strings
				if s, isStr := val.(string); isStr && s == "" {
					continue
				}
				return val, FieldTypeString, nil
			}
		}
	}
	if chain, ok := fm.sigmaToAgentFallback[strings.ToLower(fieldName)]; ok {
		for _, path := range chain {
			if val := fm.getNested(eventData, path); val != nil {
				if s, isStr := val.(string); isStr && s == "" {
					continue
				}
				return val, FieldTypeString, nil
			}
		}
	}

	// 6) Sysmon-specific paths (common Sysmon JSON layouts)
	sysmonPaths := []string{
		"Event.EventData." + fieldName,
		"EventData." + fieldName,
	}

	for _, path := range sysmonPaths {
		if val := fm.getNested(eventData, path); val != nil {
			return val, FieldTypeString, nil
		}
	}

	// 7) Broader variant search (Sigma/ECS + alternatives + case variations)
	allVariants := fm.getAllFieldVariants(fieldName)
	for _, variant := range allVariants {
		if variant == fieldName {
			continue
		}

		// Try direct
		if val, ok := eventData[variant]; ok {
			return val, FieldTypeString, nil
		}

		// Try nested
		if val := fm.getNested(eventData, variant); val != nil {
			return val, FieldTypeString, nil
		}
	}

	// Not found
	return nil, FieldTypeString, nil
}

// getAllFieldVariants returns all possible field name variants for a given field.
func (fm *FieldMapper) getAllFieldVariants(fieldName string) []string {
	variants := map[string]bool{fieldName: true}

	// Check if it's a Sigma field
	if mapping, ok := fm.sigmaToECS[fieldName]; ok {
		variants[mapping.ECSName] = true
		for _, alt := range mapping.Alternatives {
			variants[alt] = true
		}
	}

	// Check if it's an ECS field
	if mapping, ok := fm.ecsToSigma[fieldName]; ok {
		variants[mapping.SigmaName] = true
		for _, alt := range mapping.Alternatives {
			variants[alt] = true
		}
	}

	// Check alternatives
	fieldLower := strings.ToLower(fieldName)
	if mapping, ok := fm.alternatives[fieldLower]; ok {
		variants[mapping.SigmaName] = true
		variants[mapping.ECSName] = true
		for _, alt := range mapping.Alternatives {
			variants[alt] = true
		}
	}

	result := make([]string, 0, len(variants))
	for variant := range variants {
		result = append(result, variant)
	}
	return result
}

// getNested retrieves a value from nested dictionary using dot notation.
func (fm *FieldMapper) getNested(data map[string]interface{}, path string) interface{} {
	if !strings.Contains(path, ".") {
		return nil
	}

	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[part]; exists {
				current = val
				continue
			}
			// Try case-insensitive match
			for key, val := range m {
				if strings.EqualFold(key, part) {
					current = val
					goto next
				}
			}
			return nil
		next:
		} else {
			return nil
		}
	}

	return current
}

// GetFieldType returns the expected data type for a field.
func (fm *FieldMapper) GetFieldType(fieldName string) FieldType {
	// Check Sigma mapping
	if mapping, ok := fm.sigmaToECS[fieldName]; ok {
		return mapping.DataType
	}

	// Check ECS mapping
	if mapping, ok := fm.ecsToSigma[fieldName]; ok {
		return mapping.DataType
	}

	// Check alternatives
	fieldLower := strings.ToLower(fieldName)
	if mapping, ok := fm.alternatives[fieldLower]; ok {
		return mapping.DataType
	}

	return FieldTypeString // Default
}
