package alert

import (
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/google/uuid"
)

// AlertGenerator generates alerts from detection results with enrichment.
type AlertGenerator struct {
	mitreMappings map[string]string // Technique ID -> Tactic mapping
}

// NewAlertGenerator creates a new alert generator.
func NewAlertGenerator() *AlertGenerator {
	return &AlertGenerator{
		mitreMappings: initializeMitreMappings(),
	}
}

// GenerateAlert creates an alert from a detection result with enrichment.
func (ag *AlertGenerator) GenerateAlert(
	detection *domain.DetectionResult,
	event *domain.LogEvent,
) *domain.Alert {
	if detection == nil || !detection.Matched {
		return nil
	}

	// Extract MITRE ATT&CK information
	tactics := ag.extractTactics(detection.Rule.Tags)
	techniques := ag.extractTechniques(detection.Rule.Tags)

	// Calculate alert severity
	alertSeverity := ag.calculateSeverity(detection)

	// Create alert
	alert := &domain.Alert{
		ID:                ag.generateAlertID(),
		RuleID:            detection.Rule.ID,
		RuleTitle:         detection.Rule.Title,
		Severity:          alertSeverity,
		Confidence:        detection.Confidence,
		Timestamp:         time.Now(),
		EventID:           detection.Event.EventID,
		EventCategory:     detection.Event.Category,
		Product:           detection.Event.Product,
		MITRETactics:      tactics,
		MITRETechniques:   techniques,
		MatchedFields:     make(map[string]interface{}),
		MatchedSelections: detection.MatchedSelections,
		EventData:         ag.sanitizeEventData(detection.Event.RawData),
		FalsePositiveRisk: 0.0,
	}

	// Copy matched fields
	for k, v := range detection.MatchedFields {
		alert.MatchedFields[k] = v
	}

	// Add enrichment
	alert.EventData = ag.enrichEventData(event, alert.EventData)

	return alert
}

// extractTactics extracts MITRE ATT&CK tactics from rule tags.
func (ag *AlertGenerator) extractTactics(tags []string) []string {
	tacticsMap := make(map[string]bool)

	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.") {
			parts := strings.Split(tag, ".")
			if len(parts) >= 2 {
				// Extract tactic name (e.g., "initial_access" from "attack.initial_access")
				tactic := parts[1]
				// Convert to title case
				tactic = strings.Title(strings.ReplaceAll(tactic, "_", " "))
				tacticsMap[tactic] = true
			}
		}
	}

	// Also extract from techniques
	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.t") {
			techniqueID := tag[7:] // Remove "attack." prefix
			if tactic := ag.techniqueToTactic(techniqueID); tactic != "" {
				tacticsMap[tactic] = true
			}
		}
	}

	tactics := make([]string, 0, len(tacticsMap))
	for tactic := range tacticsMap {
		tactics = append(tactics, tactic)
	}

	return tactics
}

// extractTechniques extracts MITRE ATT&CK technique IDs from rule tags.
func (ag *AlertGenerator) extractTechniques(tags []string) []string {
	var techniques []string

	for _, tag := range tags {
		// Look for patterns like "attack.t1234" (ATT&CK technique IDs)
		if strings.HasPrefix(tag, "attack.t") && len(tag) > 9 {
			techniqueID := strings.ToUpper(tag[7:]) // Extract "T1234" from "attack.t1234"
			techniques = append(techniques, techniqueID)
		}
	}

	return deduplicateStrings(techniques)
}

// calculateSeverity calculates alert severity based on rule level and confidence.
func (ag *AlertGenerator) calculateSeverity(detection *domain.DetectionResult) domain.Severity {
	// Base severity from rule level
	baseSeverity := detection.Rule.Severity()

	// Adjust based on confidence
	if detection.Confidence >= 0.9 {
		// High confidence: escalate severity
		if baseSeverity < domain.SeverityCritical {
			return baseSeverity + 1
		}
	} else if detection.Confidence < 0.5 {
		// Low confidence: reduce severity
		if baseSeverity > domain.SeverityInformational {
			return baseSeverity - 1
		}
	}

	return baseSeverity
}

// enrichEventData enriches event data with additional context.
func (ag *AlertGenerator) enrichEventData(
	event *domain.LogEvent,
	eventData map[string]interface{},
) map[string]interface{} {
	if eventData == nil {
		eventData = make(map[string]interface{})
	}

	// Add parent process info if available
	if parentImage, ok := event.GetField("ParentImage"); ok {
		eventData["parent_process"] = parentImage
	}

	// Add user info if available
	if user, ok := event.GetField("User"); ok {
		eventData["user"] = user
	}

	// Add process ID if available
	if pid, ok := event.GetInt64Field("ProcessId"); ok {
		eventData["process_id"] = pid
	}

	// Add command line if available
	// Prefer EDR agent normalized key: `command_line`.
	// Fallback to legacy/case variants for backward compatibility.
	if cmdLine, ok := event.GetField("command_line"); ok {
		eventData["command_line"] = cmdLine
	} else if cmdLine, ok := event.GetField("CommandLine"); ok {
		eventData["command_line"] = cmdLine
	} else if cmdLine, ok := event.GetField("process.command_line"); ok {
		eventData["command_line"] = cmdLine
	} else if cmdLine, ok := event.GetField("data.command_line"); ok {
		eventData["command_line"] = cmdLine
	}

	return eventData
}

// sanitizeEventData creates a sanitized copy of event data.
func (ag *AlertGenerator) sanitizeEventData(rawData map[string]interface{}) map[string]interface{} {
	if rawData == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	sensitiveFields := map[string]bool{
		"password": true,
		"passwd":   true,
		"pwd":      true,
		"secret":   true,
		"token":    true,
		"api_key":  true,
		"apikey":   true,
	}

	for k, v := range rawData {
		keyLower := strings.ToLower(k)
		if sensitiveFields[keyLower] {
			sanitized[k] = "[REDACTED]"
			continue
		}
		sanitized[k] = v
	}

	return sanitized
}

// techniqueToTactic maps MITRE technique ID to tactic.
func (ag *AlertGenerator) techniqueToTactic(techniqueID string) string {
	// Remove sub-technique suffix (e.g., "T1059.001" -> "T1059")
	baseID := techniqueID
	if idx := strings.Index(techniqueID, "."); idx > 0 {
		baseID = techniqueID[:idx]
	}

	if tactic, ok := ag.mitreMappings[baseID]; ok {
		return tactic
	}

	return ""
}

// generateAlertID generates a unique alert ID (plain UUID v4). It is the
// alert's canonical identity: it becomes the sigma_alerts primary key, so
// Kafka, correlation edges, playbooks and the dashboard all share one ID.
func (ag *AlertGenerator) generateAlertID() string {
	return uuid.New().String()
}

// initializeMitreMappings initializes MITRE ATT&CK Enterprise v14 technique → tactic mappings.
// Covers all 14 tactics with 150+ base technique IDs.
//
// Source: https://attack.mitre.org/techniques/enterprise/
//
// NOTE: Some techniques map to multiple tactics (e.g., T1055 = both
// Privilege Escalation AND Defense Evasion). We pick the PRIMARY tactic
// here — the one most commonly associated with the technique in Sigma rules.
func initializeMitreMappings() map[string]string {
	return map[string]string{
		// ================================================================
		// Reconnaissance (TA0043)
		// ================================================================
		"T1595": "Reconnaissance", // Active Scanning
		"T1592": "Reconnaissance", // Gather Victim Host Information
		"T1589": "Reconnaissance", // Gather Victim Identity Information
		"T1590": "Reconnaissance", // Gather Victim Network Information
		"T1591": "Reconnaissance", // Gather Victim Org Information
		"T1596": "Reconnaissance", // Search Open Technical Databases
		"T1593": "Reconnaissance", // Search Open Websites/Domains
		"T1594": "Reconnaissance", // Search Victim-Owned Websites
		"T1597": "Reconnaissance", // Search Closed Sources
		"T1598": "Reconnaissance", // Phishing for Information

		// ================================================================
		// Resource Development (TA0042)
		// ================================================================
		"T1583": "Resource Development", // Acquire Infrastructure
		"T1584": "Resource Development", // Compromise Infrastructure
		"T1585": "Resource Development", // Establish Accounts
		"T1586": "Resource Development", // Compromise Accounts
		"T1587": "Resource Development", // Develop Capabilities
		"T1588": "Resource Development", // Obtain Capabilities
		"T1608": "Resource Development", // Stage Capabilities

		// ================================================================
		// Initial Access (TA0001)
		// ================================================================
		"T1189": "Initial Access", // Drive-by Compromise
		"T1190": "Initial Access", // Exploit Public-Facing Application
		"T1133": "Initial Access", // External Remote Services
		"T1200": "Initial Access", // Hardware Additions
		"T1566": "Initial Access", // Phishing
		"T1091": "Initial Access", // Replication Through Removable Media
		"T1195": "Initial Access", // Supply Chain Compromise
		"T1199": "Initial Access", // Trusted Relationship
		"T1078": "Initial Access", // Valid Accounts

		// ================================================================
		// Execution (TA0002)
		// ================================================================
		"T1059": "Execution", // Command and Scripting Interpreter
		"T1047": "Execution", // Windows Management Instrumentation
		"T1053": "Execution", // Scheduled Task/Job
		"T1129": "Execution", // Shared Modules
		"T1203": "Execution", // Exploitation for Client Execution
		"T1569": "Execution", // System Services
		"T1204": "Execution", // User Execution
		"T1559": "Execution", // Inter-Process Communication
		"T1106": "Execution", // Native API
		"T1648": "Execution", // Serverless Execution

		// ================================================================
		// Persistence (TA0003)
		// ================================================================
		"T1547": "Persistence", // Boot or Logon Autostart Execution
		"T1543": "Persistence", // Create or Modify System Process
		"T1546": "Persistence", // Event Triggered Execution
		// T1556: see Credential Access (primary tactic)
		"T1137": "Persistence", // Office Application Startup
		"T1542": "Persistence", // Pre-OS Boot
		"T1574": "Persistence", // Hijack Execution Flow
		"T1136": "Persistence", // Create Account
		"T1098": "Persistence", // Account Manipulation
		"T1197": "Persistence", // BITS Jobs
		"T1505": "Persistence", // Server Software Component
		"T1205": "Persistence", // Traffic Signaling

		// ================================================================
		// Privilege Escalation (TA0004)
		// ================================================================
		"T1055": "Privilege Escalation", // Process Injection
		"T1134": "Privilege Escalation", // Access Token Manipulation
		"T1068": "Privilege Escalation", // Exploitation for Privilege Escalation
		"T1548": "Privilege Escalation", // Abuse Elevation Control Mechanism
		"T1611": "Privilege Escalation", // Escape to Host

		// ================================================================
		// Defense Evasion (TA0005)
		// ================================================================
		"T1027": "Defense Evasion", // Obfuscated Files or Information
		"T1036": "Defense Evasion", // Masquerading
		"T1070": "Defense Evasion", // Indicator Removal
		"T1218": "Defense Evasion", // System Binary Proxy Execution
		"T1562": "Defense Evasion", // Impair Defenses
		"T1140": "Defense Evasion", // Deobfuscate/Decode Files
		"T1112": "Defense Evasion", // Modify Registry
		"T1564": "Defense Evasion", // Hide Artifacts
		"T1497": "Defense Evasion", // Virtualization/Sandbox Evasion
		"T1220": "Defense Evasion", // XSL Script Processing
		"T1221": "Defense Evasion", // Template Injection
		"T1202": "Defense Evasion", // Indirect Command Execution
		"T1216": "Defense Evasion", // System Script Proxy Execution
		"T1553": "Defense Evasion", // Subvert Trust Controls
		"T1480": "Defense Evasion", // Execution Guardrails
		"T1622": "Defense Evasion", // Debugger Evasion
		"T1006": "Defense Evasion", // Direct Volume Access
		"T1014": "Defense Evasion", // Rootkit
		"T1127": "Defense Evasion", // Trusted Developer Utilities Proxy Execution

		// ================================================================
		// Credential Access (TA0006)
		// ================================================================
		"T1003": "Credential Access", // OS Credential Dumping
		"T1110": "Credential Access", // Brute Force
		"T1557": "Credential Access", // Adversary-in-the-Middle
		"T1558": "Credential Access", // Steal or Forge Kerberos Tickets
		"T1555": "Credential Access", // Credentials from Password Stores
		"T1552": "Credential Access", // Unsecured Credentials
		"T1556": "Credential Access", // Modify Authentication Process
		"T1539": "Credential Access", // Steal Web Session Cookie
		"T1528": "Credential Access", // Steal Application Access Token
		"T1649": "Credential Access", // Steal or Forge Authentication Certificates
		"T1187": "Credential Access", // Forced Authentication
		"T1212": "Credential Access", // Exploitation for Credential Access
		"T1040": "Credential Access", // Network Sniffing

		// ================================================================
		// Discovery (TA0007)
		// ================================================================
		"T1082": "Discovery", // System Information Discovery
		"T1083": "Discovery", // File and Directory Discovery
		"T1087": "Discovery", // Account Discovery
		"T1016": "Discovery", // System Network Configuration Discovery
		"T1033": "Discovery", // System Owner/User Discovery
		"T1049": "Discovery", // System Network Connections Discovery
		"T1057": "Discovery", // Process Discovery
		"T1012": "Discovery", // Query Registry
		"T1018": "Discovery", // Remote System Discovery
		"T1069": "Discovery", // Permission Groups Discovery
		"T1007": "Discovery", // System Service Discovery
		"T1010": "Discovery", // Application Window Discovery
		"T1046": "Discovery", // Network Service Discovery
		"T1135": "Discovery", // Network Share Discovery
		"T1201": "Discovery", // Password Policy Discovery
		"T1482": "Discovery", // Domain Trust Discovery
		"T1518": "Discovery", // Software Discovery
		"T1124": "Discovery", // System Time Discovery
		// T1497: see Defense Evasion (primary tactic)
		"T1615": "Discovery", // Group Policy Discovery

		// ================================================================
		// Lateral Movement (TA0008)
		// ================================================================
		"T1021": "Lateral Movement", // Remote Services
		"T1570": "Lateral Movement", // Lateral Tool Transfer
		"T1563": "Lateral Movement", // Remote Service Session Hijacking
		"T1534": "Lateral Movement", // Internal Spearphishing
		"T1080": "Lateral Movement", // Taint Shared Content
		"T1550": "Lateral Movement", // Use Alternate Authentication Material

		// ================================================================
		// Collection (TA0009)
		// ================================================================
		"T1005": "Collection", // Data from Local System
		"T1113": "Collection", // Screen Capture
		"T1560": "Collection", // Archive Collected Data
		"T1115": "Collection", // Clipboard Data
		"T1119": "Collection", // Automated Collection
		"T1530": "Collection", // Data from Cloud Storage
		"T1213": "Collection", // Data from Information Repositories
		"T1025": "Collection", // Data from Removable Media
		"T1074": "Collection", // Data Staged
		"T1056": "Collection", // Input Capture
		"T1123": "Collection", // Audio Capture
		"T1125": "Collection", // Video Capture
		"T1039": "Collection", // Data from Network Shared Drive

		// ================================================================
		// Command and Control (TA0011)
		// ================================================================
		"T1071": "Command and Control", // Application Layer Protocol
		"T1105": "Command and Control", // Ingress Tool Transfer
		"T1090": "Command and Control", // Proxy
		"T1573": "Command and Control", // Encrypted Channel
		"T1572": "Command and Control", // Protocol Tunneling
		"T1568": "Command and Control", // Dynamic Resolution
		"T1095": "Command and Control", // Non-Application Layer Protocol
		"T1104": "Command and Control", // Multi-Stage Channels
		"T1132": "Command and Control", // Data Encoding
		"T1001": "Command and Control", // Data Obfuscation
		"T1008": "Command and Control", // Fallback Channels
		"T1219": "Command and Control", // Remote Access Software
		"T1102": "Command and Control", // Web Service
		"T1571": "Command and Control", // Non-Standard Port

		// ================================================================
		// Exfiltration (TA0010)
		// ================================================================
		"T1041": "Exfiltration", // Exfiltration Over C2 Channel
		"T1048": "Exfiltration", // Exfiltration Over Alternative Protocol
		"T1567": "Exfiltration", // Exfiltration Over Web Service
		"T1029": "Exfiltration", // Scheduled Transfer
		"T1537": "Exfiltration", // Transfer Data to Cloud Account
		"T1020": "Exfiltration", // Automated Exfiltration
		"T1030": "Exfiltration", // Data Transfer Size Limits
		"T1052": "Exfiltration", // Exfiltration Over Physical Medium

		// ================================================================
		// Impact (TA0040)
		// ================================================================
		"T1486": "Impact", // Data Encrypted for Impact (Ransomware)
		"T1489": "Impact", // Service Stop
		"T1490": "Impact", // Inhibit System Recovery
		"T1485": "Impact", // Data Destruction
		"T1491": "Impact", // Defacement
		"T1499": "Impact", // Endpoint Denial of Service
		"T1498": "Impact", // Network Denial of Service
		"T1496": "Impact", // Resource Hijacking (Cryptomining)
		"T1531": "Impact", // Account Access Removal
		"T1529": "Impact", // System Shutdown/Reboot
		"T1565": "Impact", // Data Manipulation
	}
}

// deduplicateStrings removes duplicate strings from a slice.
func deduplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// =============================================================================
// ATOMIC EVENT AGGREGATION - Single alert from multiple rule matches
// =============================================================================

// GenerateAggregatedAlert creates a SINGLE alert from an EventMatchResult.
// This is the key function for reducing alert fatigue.
//
// Algorithm:
//  1. Primary Rule Selection: Choose highest severity rule as the main alert
//  2. Severity Promotion: If matchCount > 3 AND severity is Low/Medium → promote to High
//  3. Combined Confidence: max(confidence) + multi-match bonus
//  4. Context Enrichment: Include all related rules that matched
//
// Returns nil if no matches exist.
func (ag *AlertGenerator) GenerateAggregatedAlert(
	matchResult *domain.EventMatchResult,
) *domain.Alert {
	if matchResult == nil || !matchResult.HasMatches() {
		return nil
	}

	// Step 1: Get the primary (highest severity) match
	primary := matchResult.HighestSeverityMatch()
	if primary == nil || primary.Rule == nil {
		return nil
	}

	// Step 2: Extract MITRE ATT&CK information from ALL matched rules
	allTechniques := matchResult.AllMITRETechniques()
	tactics := ag.extractTacticsFromTechniques(allTechniques)

	// Step 3: Calculate original severity from primary rule
	originalSeverity := primary.Rule.Severity()

	// Step 4: Determine final severity (with potential promotion)
	finalSeverity, wasPromoted := ag.calculateAggregatedSeverity(
		originalSeverity,
		matchResult.MatchCount(),
		matchResult.CombinedConfidence(),
	)

	// Step 5: Build the aggregated alert with EXPLICIT field assignment
	matchCount := matchResult.MatchCount()
	combinedConf := matchResult.CombinedConfidence()
	relatedTitles := matchResult.RelatedRuleTitles()
	relatedIDs := matchResult.RelatedRuleIDs()

	alert := &domain.Alert{
		ID:                ag.generateAlertID(),
		RuleID:            primary.Rule.ID,
		RuleTitle:         primary.Rule.Title,
		Severity:          finalSeverity,
		Confidence:        primary.Confidence,
		Timestamp:         matchResult.Timestamp,
		EventID:           matchResult.Event.EventID,
		EventCategory:     matchResult.Event.Category,
		Product:           matchResult.Event.Product,
		MITRETactics:      tactics,
		MITRETechniques:   allTechniques,
		MatchedFields:     matchResult.AllMatchedFields(),
		MatchedSelections: primary.MatchedSelections,
		EventData:         ag.sanitizeEventData(matchResult.Event.RawData),
		FalsePositiveRisk: 0.0,

		// Aggregation fields - EXPLICIT assignment to ensure they're set
		MatchCount:         matchCount,
		RelatedRules:       relatedTitles,
		RelatedRuleIDs:     relatedIDs,
		CombinedConfidence: combinedConf,
		OriginalSeverity:   originalSeverity,
		SeverityPromoted:   wasPromoted,
	}

	// Step 6: Add enrichment from event
	alert.EventData = ag.enrichEventData(matchResult.Event, alert.EventData)

	return alert
}

// calculateAggregatedSeverity returns the alert severity for an aggregated
// alert: the level of the highest-severity matching rule, unchanged.
//
// Sigma defines `level` as the rule author's assessment of the detection
// (fidelity x impact); the platform reports it as-is. Several rules matching
// the SAME event (e.g. three PowerShell download rules on one command line)
// are correlated, not independent evidence, so they must not promote the
// severity — that inflated High to Critical routinely. Multiple matches are
// still reflected in the risk score's bounded correlation bonus and in
// related_rules; cross-event correlation belongs to correlation rules.
func (ag *AlertGenerator) calculateAggregatedSeverity(
	baseSeverity domain.Severity,
	_ int,
	_ float64,
) (domain.Severity, bool) {
	return baseSeverity, false
}

// extractTacticsFromTechniques extracts MITRE tactics from technique IDs.
func (ag *AlertGenerator) extractTacticsFromTechniques(techniques []string) []string {
	tacticsMap := make(map[string]bool)

	for _, technique := range techniques {
		if tactic := ag.techniqueToTactic(technique); tactic != "" {
			tacticsMap[tactic] = true
		}
	}

	tactics := make([]string, 0, len(tacticsMap))
	for tactic := range tacticsMap {
		tactics = append(tactics, tactic)
	}

	return tactics
}
