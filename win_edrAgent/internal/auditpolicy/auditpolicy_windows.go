//go:build windows
// +build windows

// Package auditpolicy makes sure the Windows advanced audit subcategories the
// agent's event-log telemetry depends on are enabled, and reverts exactly what
// it changed on uninstall.
//
// Several Security records the detection rules use are not written by default:
// service installation (4697, "Security System Extension") and scheduled task
// registration (4698-4702, "Other Object Access Events") among them. The
// agent only ADDS the success/failure flags a subcategory is missing; it never
// removes auditing an administrator configured. The original value of every
// subcategory it touched is recorded under HKLM\SOFTWARE\EDR\Agent so the
// uninstall path restores it. It uses the Audit* API, which is locale
// independent (auditpol's text output is localized).
package auditpolicy

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	auditSuccess = 0x1 // POLICY_AUDIT_EVENT_SUCCESS
	auditFailure = 0x2 // POLICY_AUDIT_EVENT_FAILURE
	auditNone    = 0x4 // POLICY_AUDIT_EVENT_NONE (set: clear both)

	agentStateKey = `SOFTWARE\EDR\Agent`
	markerValue   = "AuditPolicyEnabledByAgent"
)

// Subcategory is one advanced audit subcategory and the flags the agent needs.
type Subcategory struct {
	Name  string
	GUID  string
	Flags uint32
}

// Required lists the subcategories behind the Security records the agent
// forwards. GUIDs as reported by `auditpol /list /subcategory:* /v`.
var Required = []Subcategory{
	{"Security System Extension", "{0CCE9211-69AE-11D9-BED3-505054503030}", auditSuccess},            // 4697
	{"Other Object Access Events", "{0CCE9227-69AE-11D9-BED3-505054503030}", auditSuccess},           // 4698-4702
	{"User Account Management", "{0CCE9235-69AE-11D9-BED3-505054503030}", auditSuccess},              // 4720-4726, 4738, 4781
	{"Security Group Management", "{0CCE9237-69AE-11D9-BED3-505054503030}", auditSuccess},            // 4728/4732/4756
	{"Audit Policy Change", "{0CCE922F-69AE-11D9-BED3-505054503030}", auditSuccess},                  // 4719
	{"Logon", "{0CCE9215-69AE-11D9-BED3-505054503030}", auditSuccess | auditFailure},                 // 4624/4625/4648
	{"Credential Validation", "{0CCE923F-69AE-11D9-BED3-505054503030}", auditSuccess | auditFailure}, // 4776
}

type auditPolicyInformation struct {
	SubCategory windows.GUID
	Auditing    uint32
	Category    windows.GUID
}

var (
	modAdvapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuerySystemPolicy = modAdvapi32.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy   = modAdvapi32.NewProc("AuditSetSystemPolicy")
	procAuditFree              = modAdvapi32.NewProc("AuditFree")
)

func query(guid windows.GUID) (uint32, error) {
	var out *auditPolicyInformation
	r, _, err := procAuditQuerySystemPolicy.Call(uintptr(unsafe.Pointer(&guid)), 1, uintptr(unsafe.Pointer(&out)))
	// BOOLEAN return: only the low byte is defined.
	if byte(r) == 0 || out == nil {
		if err == nil || err == windows.ERROR_SUCCESS {
			err = fmt.Errorf("AuditQuerySystemPolicy failed")
		}
		return 0, err
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(out)))
	return out.Auditing & (auditSuccess | auditFailure), nil
}

func set(guid windows.GUID, flags uint32) error {
	if flags == 0 {
		flags = auditNone
	}
	info := auditPolicyInformation{SubCategory: guid, Auditing: flags}
	r, _, err := procAuditSetSystemPolicy.Call(uintptr(unsafe.Pointer(&info)), 1)
	if byte(r) == 0 { // BOOLEAN return
		if err == nil || err == windows.ERROR_SUCCESS {
			err = fmt.Errorf("AuditSetSystemPolicy failed")
		}
		return err
	}
	return nil
}

// enableSecurityPrivilege turns on SeSecurityPrivilege in the process token:
// the Audit* API requires it enabled, and it is present but disabled by
// default even for LocalSystem.
func enableSecurityPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeSecurityPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return err
	}
	// AdjustTokenPrivileges succeeds with ERROR_NOT_ALL_ASSIGNED when the
	// account does not hold the privilege.
	if e := windows.GetLastError(); e == windows.ERROR_NOT_ALL_ASSIGNED {
		return e
	}
	return nil
}

// Missing returns the flags required but not present (pure; unit tested).
func Missing(current, required uint32) uint32 { return required &^ current }

// Ensure enables any missing required flags and records the original values.
// It returns the names of the subcategories it changed.
func Ensure() ([]string, error) {
	if err := procAuditQuerySystemPolicy.Find(); err != nil {
		return nil, fmt.Errorf("audit API unavailable: %w", err)
	}
	if err := enableSecurityPrivilege(); err != nil {
		return nil, fmt.Errorf("SeSecurityPrivilege unavailable (agent must run as LocalSystem): %w", err)
	}
	recorded := readMarker()
	var changed []string
	var errs []string
	for _, sc := range Required {
		guid, err := windows.GUIDFromString(sc.GUID)
		if err != nil {
			errs = append(errs, sc.Name+": "+err.Error())
			continue
		}
		cur, err := query(guid)
		if err != nil {
			errs = append(errs, sc.Name+": query: "+err.Error())
			continue
		}
		miss := Missing(cur, sc.Flags)
		if miss == 0 {
			continue
		}
		if err := set(guid, cur|miss); err != nil {
			errs = append(errs, sc.Name+": set: "+err.Error())
			continue
		}
		if _, seen := recorded[sc.GUID]; !seen {
			recorded[sc.GUID] = cur // keep the first original across restarts
		}
		changed = append(changed, sc.Name)
	}
	if len(changed) > 0 {
		writeMarker(recorded)
	}
	if len(errs) > 0 {
		return changed, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return changed, nil
}

// Revert restores the original values of the subcategories the agent changed
// (called on uninstall). Subcategories it never touched are left alone.
func Revert() {
	recorded := readMarker()
	if len(recorded) > 0 {
		_ = enableSecurityPrivilege()
	}
	for g, original := range recorded {
		if guid, err := windows.GUIDFromString(g); err == nil && isRequired(g) {
			_ = set(guid, original)
		}
	}
	if sk, err := registry.OpenKey(registry.LOCAL_MACHINE, agentStateKey, registry.SET_VALUE); err == nil {
		_ = sk.DeleteValue(markerValue)
		sk.Close()
	}
}

func isRequired(g string) bool {
	for _, sc := range Required {
		if strings.EqualFold(sc.GUID, g) {
			return true
		}
	}
	return false
}

// EncodeMarker / DecodeMarker serialize "GUID=flags;GUID=flags" (pure).
func EncodeMarker(m map[string]uint32) string {
	parts := make([]string, 0, len(m))
	for _, sc := range Required { // stable order
		if v, ok := m[sc.GUID]; ok {
			parts = append(parts, sc.GUID+"="+strconv.FormatUint(uint64(v), 10))
		}
	}
	return strings.Join(parts, ";")
}

func DecodeMarker(s string) map[string]uint32 {
	out := map[string]uint32{}
	for _, part := range strings.Split(s, ";") {
		g, v, ok := strings.Cut(part, "=")
		if !ok || !isRequired(g) {
			continue
		}
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			out[g] = uint32(n) & (auditSuccess | auditFailure)
		}
	}
	return out
}

func readMarker() map[string]uint32 {
	sk, err := registry.OpenKey(registry.LOCAL_MACHINE, agentStateKey, registry.QUERY_VALUE)
	if err != nil {
		return map[string]uint32{}
	}
	defer sk.Close()
	v, _, err := sk.GetStringValue(markerValue)
	if err != nil {
		return map[string]uint32{}
	}
	return DecodeMarker(v)
}

func writeMarker(m map[string]uint32) {
	if sk, _, err := registry.CreateKey(registry.LOCAL_MACHINE, agentStateKey, registry.SET_VALUE); err == nil {
		_ = sk.SetStringValue(markerValue, EncodeMarker(m))
		sk.Close()
	}
}
