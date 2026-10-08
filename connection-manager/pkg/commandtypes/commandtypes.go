// Package commandtypes maps REST/playbook command type names to the agent
// protocol's CommandType. It is shared by the manual command API and the
// server-side response engine so both dispatch identically.
package commandtypes

import (
	"strings"

	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// Normalize lowercases and trims a command type name.
func Normalize(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// ToProto maps a command type name to the proto CommandType. Unknown names
// map to COMMAND_TYPE_UNSPECIFIED, which callers must reject: the agent
// would otherwise log "unknown command type" and drop the command.
func ToProto(cmdType string) edrv1.CommandType {
	switch Normalize(cmdType) {
	case "kill_process", "terminate_process":
		return edrv1.CommandType_COMMAND_TYPE_TERMINATE_PROCESS
	case "collect_logs", "collect_forensics":
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	case "quarantine_file":
		return edrv1.CommandType(13) // COMMAND_TYPE_QUARANTINE_FILE
	case "block_ip":
		return edrv1.CommandType(14)
	case "unblock_ip":
		return edrv1.CommandType(15)
	case "block_domain":
		return edrv1.CommandType(16)
	case "unblock_domain":
		return edrv1.CommandType(17)
	case "update_signatures":
		return edrv1.CommandType(18)
	case "restore_quarantine_file":
		return edrv1.CommandType(19) // COMMAND_TYPE_RESTORE_QUARANTINE_FILE
	case "delete_quarantine_file":
		return edrv1.CommandType(20) // COMMAND_TYPE_DELETE_QUARANTINE_FILE
	case "scan_file", "scan_memory":
		// Map to COLLECT_FORENSICS so the agent receives it; params carry sub-type.
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	case "isolate", "isolate_network":
		return edrv1.CommandType_COMMAND_TYPE_ISOLATE
	case "unisolate", "unisolate_network", "restore_network":
		return edrv1.CommandType_COMMAND_TYPE_UNISOLATE
	case "restart_agent", "restart_service":
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "stop_agent", "stop_service":
		// Stop only — agent checks Parameters["mode"] == "stop"
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "start_agent", "start_service":
		// Start only — agent checks Parameters["mode"] == "start"
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "restart", "restart_machine":
		return edrv1.CommandType(10)
	case "shutdown", "shutdown_machine":
		return edrv1.CommandType(11)
	case "update_agent":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT
	case "uninstall_agent":
		// Proto enum value 21 — server is the sole authority for agent uninstall.
		return edrv1.CommandType(21)
	case "update_config", "update_policy", "update_vuln_config":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "enable_sysmon", "disable_sysmon":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "update_filter_policy":
		return edrv1.CommandType(12) // COMMAND_TYPE_UPDATE_FILTER_POLICY
	case "adjust_rate":
		return edrv1.CommandType_COMMAND_TYPE_ADJUST_RATE
	case "run_cmd", "custom":
		return edrv1.CommandType(9) // COMMAND_TYPE_RUN_CMD
	case "post_isolation_triage":
		return edrv1.CommandType_COMMAND_TYPE_POST_ISOLATION_TRIAGE
	case "process_tree_snapshot":
		return edrv1.CommandType_COMMAND_TYPE_PROCESS_TREE_SNAPSHOT
	case "persistence_scan":
		return edrv1.CommandType_COMMAND_TYPE_PERSISTENCE_SCAN
	case "lsass_access_audit":
		return edrv1.CommandType_COMMAND_TYPE_LSASS_ACCESS_AUDIT
	case "filesystem_timeline":
		return edrv1.CommandType_COMMAND_TYPE_FILESYSTEM_TIMELINE
	case "network_last_seen":
		return edrv1.CommandType_COMMAND_TYPE_NETWORK_LAST_SEEN
	case "agent_integrity_check":
		return edrv1.CommandType_COMMAND_TYPE_AGENT_INTEGRITY_CHECK
	case "memory_dump":
		return edrv1.CommandType_COMMAND_TYPE_MEMORY_DUMP
	default:
		return edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED
	}
}
