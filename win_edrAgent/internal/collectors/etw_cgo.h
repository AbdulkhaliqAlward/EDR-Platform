#ifndef ETW_CGO_H
#define ETW_CGO_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <wchar.h>

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif

#ifndef EVENT_TRACE_FLAG_PROCESS
#define EVENT_TRACE_FLAG_PROCESS 0x00000001
#endif

#ifndef EVENT_TRACE_FLAG_IMAGE_LOAD
#define EVENT_TRACE_FLAG_IMAGE_LOAD 0x00000004
#endif

#ifndef EVENT_TRACE_FLAG_FILE_IO_INIT
#define EVENT_TRACE_FLAG_FILE_IO_INIT 0x04000000
#endif

#ifndef EVENT_TRACE_SYSTEM_LOGGER_MODE
#define EVENT_TRACE_SYSTEM_LOGGER_MODE 0x02000000
#endif

// =======================================================================
// Pre-parsed event structs passed from C to Go.
// All field extraction happens synchronously in the C callback
// so that data is captured before short-lived processes exit.
// =======================================================================

// Process create / terminate event.
typedef struct {
    DWORD processId;
    DWORD parentId;
    BYTE  opcode;       // 1=Start, 2=End
    BYTE  _pad[3];
    char  imageFileName[260];   // ANSI short name from kernel event
    LONGLONG eventTime;        // ProcessTrace converts this to UTC FILETIME
    WCHAR commandLine[4096];    // Unicode full command line
} ParsedProcessEvent;

// Image (DLL/EXE) load / unload event.
typedef struct {
    DWORD     processId;
    DWORD     threadId;
    BYTE      opcode;       // 10=Load, 2/3=Unload
    BYTE      _pad[3];
    ULONGLONG imageBase;
    ULONG     imageSize;
    WCHAR     imagePath[1024];  // Full Unicode path to the loaded image
} ParsedImageLoadEvent;

// File I/O event (create/open, delete, rename).
// Only Create (64) carries a path; Delete (70) / Rename (71) carry the
// FileObject, resolved in Go from the FileObject seen at Create time.
typedef struct {
    DWORD     processId;    // EventHeader.ProcessId (may be -1: resolve via ttid)
    DWORD     threadId;
    BYTE      opcode;       // 64=Create, 70=Delete, 71=Rename
    BYTE      _pad[3];
    ULONG     createOptions;  // Create: high byte = CreateDisposition
    ULONGLONG fileObject;     // kernel FILE_OBJECT address (correlation key)
    ULONGLONG ttid;           // issuing thread id
    WCHAR     filePath[1024]; // Create: full Unicode path of the target file
} ParsedFileIoEvent;

// =======================================================================
// Phase 1: New event structs for DNS, Pipe, and Process Access
// =======================================================================

// DNS query completed event (Microsoft-Windows-DNS-Client, EventID 3006).
// Provides the domain queried, result, and originating process.
typedef struct {
    DWORD processId;
    DWORD threadId;
    DWORD queryStatus;          // DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)
    DWORD queryType;            // DNS record type (1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT)
    WCHAR queryName[512];       // Domain name queried
    WCHAR queryResults[2048];   // Semicolon-separated answer records
} ParsedDnsEvent;

// Named pipe event (detected from kernel FileIo when path contains \\Device\\NamedPipe\\).
typedef struct {
    DWORD processId;
    DWORD threadId;
    BYTE  opcode;               // 64=PipeCreate, 0=PipeConnect
    BYTE  _pad[3];
    WCHAR pipeName[512];        // Pipe name (e.g., "\\.\pipe\evil")
} ParsedPipeEvent;

// Process access event (Microsoft-Windows-Kernel-Audit-API-Calls, EventID 1=OpenProcess).
// Detects when one process opens a handle to another with sensitive access rights.
typedef struct {
    DWORD callerPid;            // Source process ID (the one calling OpenProcess)
    DWORD targetPid;            // Target process ID (LSASS, csrss, etc.)
    DWORD desiredAccess;        // Access mask requested (e.g., 0x1F0FFF = PROCESS_ALL_ACCESS)
    DWORD returnCode;           // NTSTATUS return code (0 = success)
} ParsedProcessAccessEvent;

// Session management — kernel trace (Process + ImageLoad + FileIO)
int StartKernelProcessSession(
    const wchar_t* sessionName,
    const GUID*    providerGuid,
    UCHAR          level,
    ULONGLONG      matchAnyKeyword);

int ProcessKernelEvents(const wchar_t* sessionName, void* goContextKey);
void StopKernelSession(const GUID* providerGuid);
int KillNamedSession(const wchar_t* sessionName);

// Session management — user-mode ETW providers (DNS, ProcessAccess)
int StartUserModeSession(
    const wchar_t* sessionName,
    const GUID*    providerGuid,
    UCHAR          level,
    ULONGLONG      matchAnyKeyword);

int ProcessUserModeEvents(const wchar_t* sessionName, void* goContextKey);

#endif // ETW_CGO_H

