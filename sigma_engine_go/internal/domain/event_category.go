package domain

// EventCategory represents the category of a security event.
type EventCategory string

const (
	EventCategoryUnknown            EventCategory = "unknown"
	EventCategoryProcessCreation    EventCategory = "process_creation"
	EventCategoryProcessTermination EventCategory = "process_termination"
	EventCategoryNetworkConnection EventCategory = "network_connection"
	EventCategoryFileEvent          EventCategory = "file_event"
	EventCategoryFileAccess         EventCategory = "file_access"
	EventCategoryFileDelete         EventCategory = "file_delete"
	EventCategoryFileRename         EventCategory = "file_rename"
	EventCategoryFileChange         EventCategory = "file_change"
	EventCategoryRegistryEvent      EventCategory = "registry_event"
	EventCategoryRegistryAdd        EventCategory = "registry_add"
	EventCategoryRegistryDelete     EventCategory = "registry_delete"
	EventCategoryRegistrySet        EventCategory = "registry_set"
	EventCategoryRegistryRename     EventCategory = "registry_rename"
	EventCategoryDriverLoad         EventCategory = "driver_load"
	EventCategoryImageLoad          EventCategory = "image_load"
	EventCategoryDNSQuery           EventCategory = "dns_query"
	EventCategoryPipeCreated        EventCategory = "pipe_created"
	EventCategoryPipeConnected      EventCategory = "pipe_connected"
	EventCategoryWMIEvent           EventCategory = "wmi_event"
	EventCategoryProcessAccess      EventCategory = "process_access"
	EventCategoryCreateRemoteThread EventCategory = "create_remote_thread"
	EventCategoryRawAccessThread    EventCategory = "raw_access_thread"
	EventCategoryCreateStreamHash   EventCategory = "create_stream_hash"
	EventCategoryProcessTampering   EventCategory = "process_tampering"
	EventCategoryAuthentication     EventCategory = "authentication"
	EventCategoryServiceCreation    EventCategory = "service_creation"
	EventCategoryScheduledTask     EventCategory = "scheduled_task"
	EventCategoryUserManagement     EventCategory = "user_management"
	EventCategoryGroupManagement    EventCategory = "group_management"
	EventCategoryPowerShell         EventCategory = "powershell"
	// Sigma PowerShell logsource categories.
	EventCategoryPsScript EventCategory = "ps_script" // Script Block Logging, EventID 4104
	EventCategoryPsModule EventCategory = "ps_module" // Module Logging, EventID 4103

	// EventCategoryClipboard is agent clipboard telemetry (no SigmaHQ category).
	EventCategoryClipboard EventCategory = "clipboard"
)

// EventIDToCategory maps Windows EventIDs to event categories.
var EventIDToCategory = map[int]EventCategory{
	1:    EventCategoryProcessCreation,
	3:    EventCategoryNetworkConnection,
	5:    EventCategoryProcessTermination,
	6:    EventCategoryDriverLoad,
	7:    EventCategoryImageLoad,
	8:    EventCategoryCreateRemoteThread,
	9:    EventCategoryRawAccessThread,
	10:   EventCategoryProcessAccess,
	11:   EventCategoryFileEvent,
	12:   EventCategoryRegistryEvent,
	13:   EventCategoryRegistrySet,
	14:   EventCategoryRegistryRename,
	15:   EventCategoryFileAccess,
	17:   EventCategoryPipeCreated,
	18:   EventCategoryPipeConnected,
	19:   EventCategoryWMIEvent,
	20:   EventCategoryWMIEvent,
	21:   EventCategoryWMIEvent,
	22:   EventCategoryDNSQuery,
	23:   EventCategoryFileDelete,
	25:   EventCategoryProcessTampering,
	26:   EventCategoryFileDelete,
	4103: EventCategoryPsModule,
	4104: EventCategoryPsScript,
	4105: EventCategoryPowerShell,
	4106: EventCategoryPowerShell,
	4624: EventCategoryAuthentication,
	4625: EventCategoryAuthentication,
	4648: EventCategoryAuthentication,
	4672: EventCategoryAuthentication,
	4688: EventCategoryProcessCreation,
	4689: EventCategoryProcessTermination,
	4697: EventCategoryServiceCreation,
	4698: EventCategoryScheduledTask,
	4699: EventCategoryScheduledTask,
	4700: EventCategoryScheduledTask,
	4701: EventCategoryScheduledTask,
	4702: EventCategoryScheduledTask,
	4720: EventCategoryUserManagement,
	4722: EventCategoryUserManagement,
	4723: EventCategoryUserManagement,
	4724: EventCategoryUserManagement,
	4725: EventCategoryUserManagement,
	4726: EventCategoryUserManagement,
	4728: EventCategoryGroupManagement,
	4732: EventCategoryGroupManagement,
	4756: EventCategoryGroupManagement,
}

// InferCategoryFromEventID returns the event category for a given EventID.
func InferCategoryFromEventID(eventID int) EventCategory {
	if cat, ok := EventIDToCategory[eventID]; ok {
		return cat
	}
	return EventCategoryUnknown
}

// ExpandCategories returns the Sigma logsource categories an event of the
// given primary category must be evaluated against: the primary category
// itself plus its generic parent. In Sigma, registry_event is the umbrella
// category for every registry operation, so registry_add / registry_delete /
// registry_set / registry_rename events must also reach registry_event rules.
func ExpandCategories(primary EventCategory) []EventCategory {
	switch primary {
	case EventCategoryRegistryAdd, EventCategoryRegistryDelete,
		EventCategoryRegistrySet, EventCategoryRegistryRename:
		return []EventCategory{primary, EventCategoryRegistryEvent}
	default:
		return []EventCategory{primary}
	}
}

