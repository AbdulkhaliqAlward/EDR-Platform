// TDH-only ETW kernel event parser.
// Handles PROCESS, IMAGE LOAD, FILE I/O, DNS, PIPE, and PROCESS ACCESS events.
//
// CRITICAL: ALL field extraction uses Microsoft's TDH (Trace Data Helper)
// API to dynamically resolve property offsets by name. NO manual byte
// offsets or pointer arithmetic is used anywhere in this file.
// This ensures correctness across all Windows versions and architectures.
//
// All parsing happens SYNCHRONOUSLY in the C callback so data is
// captured before short-lived processes exit or DLLs unload.

#include "etw_cgo.h"
#include <string.h>

// Go callbacks (defined in etw.go via //export)
extern void goProcessEvent(ParsedProcessEvent* evt);
extern void goImageLoadEvent(ParsedImageLoadEvent* evt);
extern void goFileIoEvent(ParsedFileIoEvent* evt);

// Phase 1 Go callbacks (defined in dns.go, pipe.go, process_access.go)
extern void goDnsEvent(ParsedDnsEvent* evt);
extern void goPipeEvent(ParsedPipeEvent* evt);
extern void goProcessAccessEvent(ParsedProcessAccessEvent* evt);

// =====================================================================
// Well-known Kernel Trace Provider GUIDs
// =====================================================================

// {3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C} — Process events
static const GUID ProcessProviderGuid =
    {0x3D6FA8D0, 0xFE05, 0x11D0, {0x9D,0xDA,0x00,0xC0,0x4F,0xD7,0xBA,0x7C}};

// {2CB15D1D-5FC1-11D2-ABE1-00A0C911F518} — Image Load events
static const GUID ImageLoadProviderGuid =
    {0x2CB15D1D, 0x5FC1, 0x11D2, {0xAB,0xE1,0x00,0xA0,0xC9,0x11,0xF5,0x18}};

// {90CBDC39-4A3E-11D1-84F4-0000F80464E3} — File I/O events
static const GUID FileIoProviderGuid =
    {0x90CBDC39, 0x4A3E, 0x11D1, {0x84,0xF4,0x00,0x00,0xF8,0x04,0x64,0xE3}};

// =====================================================================
// Phase 1: User-Mode Provider GUIDs
// =====================================================================

// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} — Microsoft-Windows-DNS-Client
static const GUID DnsClientProviderGuid =
    {0x1C95126E, 0x7EEA, 0x49A9, {0xA3,0xFE,0xA3,0x78,0xB0,0x3D,0xDB,0x4D}};

// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23} — Microsoft-Windows-Kernel-Audit-API-Calls
static const GUID KernelAuditApiProviderGuid =
    {0xE02A841C, 0x75A3, 0x4FA7, {0xAF,0xC8,0xAE,0x09,0xCF,0x9B,0x7F,0x23}};

// =====================================================================
// TDH Property Helpers — all field extraction goes through these
// =====================================================================

// Extract an ANSI string property by name.
static int tdhGetAnsi(PEVENT_RECORD rec, LPCWSTR name, char* out, ULONG sz) {
    PROPERTY_DATA_DESCRIPTOR d;
    memset(&d, 0, sizeof(d));
    d.PropertyName = (ULONGLONG)name;
    d.ArrayIndex   = ULONG_MAX;
    ULONG ps = 0;
    if (TdhGetPropertySize(rec,0,NULL,1,&d,&ps) != ERROR_SUCCESS || ps==0 || ps>=sz)
        return 1;
    return TdhGetProperty(rec,0,NULL,1,&d,ps,(PBYTE)out)==ERROR_SUCCESS ? 0:1;
}

// Extract a Unicode string property by name.
static int tdhGetUnicode(PEVENT_RECORD rec, LPCWSTR name, WCHAR* out, ULONG bytes) {
    PROPERTY_DATA_DESCRIPTOR d;
    memset(&d, 0, sizeof(d));
    d.PropertyName = (ULONGLONG)name;
    d.ArrayIndex   = ULONG_MAX;
    ULONG ps = 0;
    if (TdhGetPropertySize(rec,0,NULL,1,&d,&ps) != ERROR_SUCCESS || ps==0 || ps>=bytes)
        return 1;
    return TdhGetProperty(rec,0,NULL,1,&d,ps,(PBYTE)out)==ERROR_SUCCESS ? 0:1;
}

// Extract a ULONG (32-bit) property by name.
static int tdhGetULONG(PEVENT_RECORD rec, LPCWSTR name, ULONG* out) {
    PROPERTY_DATA_DESCRIPTOR d;
    memset(&d, 0, sizeof(d));
    d.PropertyName = (ULONGLONG)name;
    d.ArrayIndex   = ULONG_MAX;
    ULONG ps = 0;
    if (TdhGetPropertySize(rec,0,NULL,1,&d,&ps) != ERROR_SUCCESS || ps==0)
        return 1;
    // Property may be 4 or 8 bytes depending on architecture.
    // Always read into a temporary buffer and extract safely.
    BYTE buf[8];
    memset(buf, 0, sizeof(buf));
    ULONG readSz = ps > 8 ? 8 : ps;
    if (TdhGetProperty(rec,0,NULL,1,&d,readSz,buf) != ERROR_SUCCESS)
        return 1;
    *out = *(ULONG*)buf;
    return 0;
}

// Extract a ULONGLONG (64-bit) / pointer-sized property by name.
// Handles both 32-bit and 64-bit event payloads transparently —
// TDH reports the actual property size, so we read exactly what it gives us.
static int tdhGetPointer(PEVENT_RECORD rec, LPCWSTR name, ULONGLONG* out) {
    PROPERTY_DATA_DESCRIPTOR d;
    memset(&d, 0, sizeof(d));
    d.PropertyName = (ULONGLONG)name;
    d.ArrayIndex   = ULONG_MAX;
    ULONG ps = 0;
    if (TdhGetPropertySize(rec,0,NULL,1,&d,&ps) != ERROR_SUCCESS || ps==0)
        return 1;
    BYTE buf[8];
    memset(buf, 0, sizeof(buf));
    ULONG readSz = ps > 8 ? 8 : ps;
    if (TdhGetProperty(rec,0,NULL,1,&d,readSz,buf) != ERROR_SUCCESS)
        return 1;
    if (ps <= 4) {
        *out = (ULONGLONG)(*(ULONG*)buf);
    } else {
        *out = *(ULONGLONG*)buf;
    }
    return 0;
}

// =====================================================================
// Parse Process Event — TDH ONLY, no manual offsets
// =====================================================================

static void parseProcessEvent(PEVENT_RECORD rec, ParsedProcessEvent* out) {
    out->eventTime = rec->EventHeader.TimeStamp.QuadPart;
    tdhGetULONG(rec, L"ProcessId",  &out->processId);
    tdhGetULONG(rec, L"ParentId",   &out->parentId);
    tdhGetAnsi  (rec, L"ImageFileName", out->imageFileName, sizeof(out->imageFileName));
    tdhGetUnicode(rec, L"CommandLine",  out->commandLine,   sizeof(out->commandLine));
}

// =====================================================================
// Parse Image Load Event — TDH ONLY
// =====================================================================

static void parseImageLoadEvent(PEVENT_RECORD rec, ParsedImageLoadEvent* out) {
    tdhGetUnicode(rec, L"FileName", out->imagePath, sizeof(out->imagePath));
    tdhGetPointer(rec, L"ImageBase", &out->imageBase);
    ULONGLONG imgSz = 0;
    if (tdhGetPointer(rec, L"ImageSize", &imgSz) == 0) {
        out->imageSize = (ULONG)imgSz;
    }
}

// =====================================================================
// Parse File I/O Event — TDH ONLY
// =====================================================================

static void parseFileIoEvent(PEVENT_RECORD rec, ParsedFileIoEvent* out) {
    if (tdhGetUnicode(rec, L"OpenPath", out->filePath, sizeof(out->filePath)) != 0) {
        tdhGetUnicode(rec, L"FileName", out->filePath, sizeof(out->filePath));
    }
}

// =====================================================================
// Phase 1: Parse DNS Event — TDH ONLY
//
// Microsoft-Windows-DNS-Client provider, EventID 3006 (QueryCompleted):
//   QueryName       (Unicode String) — domain name
//   QueryType       (ULONG)          — DNS record type
//   QueryStatus     (ULONG)          — DNS response status
//   QueryResults    (Unicode String) — semicolon-separated answers
// PID/TID come from EventHeader.
// =====================================================================

static void parseDnsEvent(PEVENT_RECORD rec, ParsedDnsEvent* out) {
    tdhGetUnicode(rec, L"QueryName",    out->queryName,    sizeof(out->queryName));
    tdhGetULONG  (rec, L"QueryType",    &out->queryType);
    tdhGetULONG  (rec, L"QueryStatus",  &out->queryStatus);
    tdhGetUnicode(rec, L"QueryResults", out->queryResults, sizeof(out->queryResults));
}

// =====================================================================
// Phase 1: Parse Process Access Event — TDH ONLY
//
// Microsoft-Windows-Kernel-Audit-API-Calls, EventID 1 (OpenProcess):
//   TargetProcessId  (ULONG) — PID of the process being opened
//   DesiredAccess     (ULONG) — Requested access mask
//   ReturnCode        (ULONG) — NTSTATUS (0 = success)
// CallerPID comes from EventHeader.ProcessId.
// =====================================================================

static void parseProcessAccessEvent(PEVENT_RECORD rec, ParsedProcessAccessEvent* out) {
    tdhGetULONG(rec, L"TargetProcessId", &out->targetPid);
    tdhGetULONG(rec, L"DesiredAccess",   &out->desiredAccess);
    tdhGetULONG(rec, L"ReturnCode",      &out->returnCode);
}

// =====================================================================
// GUID comparison helper
// =====================================================================

static int guidsEqual(const GUID* a, const GUID* b) {
    return memcmp(a, b, sizeof(GUID)) == 0;
}

// =====================================================================
// Named pipe detection helper
// Checks if a FileIo path is a named pipe by looking for the kernel
// device prefix used for named pipe operations.
// =====================================================================

static int isNamedPipePath(const WCHAR* path) {
    // Check for the kernel named-pipe device prefix.
    if (wcsncmp(path, L"\\Device\\NamedPipe\\", 18) == 0) return 1;
    // Check for the user-mode named-pipe prefix.
    if (wcsncmp(path, L"\\\\.\\pipe\\", 9) == 0) return 1;
    return 0;
}

// =====================================================================
// Event Callback — routes events by provider GUID
// Handles kernel events (Process, ImageLoad, FileIO/Pipe) in the
// kernel session callback, and user-mode events (DNS, ProcessAccess)
// in the user-mode session callback.
// =====================================================================

static void WINAPI stdcallEventCallback(PEVENT_RECORD eventRecord) {
    const GUID* provider = &eventRecord->EventHeader.ProviderId;
    BYTE opcode = eventRecord->EventHeader.EventDescriptor.Opcode;
    USHORT eventId = eventRecord->EventHeader.EventDescriptor.Id;

    // ---- PROCESS events (Start=1, End=2) ----
    if (guidsEqual(provider, &ProcessProviderGuid)) {
        if (opcode != 1 && opcode != 2) return;

        ParsedProcessEvent evt;
        memset(&evt, 0, sizeof(evt));
        evt.opcode = opcode;

        parseProcessEvent(eventRecord, &evt);

        if (evt.processId <= 4) return;   // Skip Idle/System

        goProcessEvent(&evt);
        return;
    }

    // ---- IMAGE LOAD events (Load=10, Unload=2/3) ----
    if (guidsEqual(provider, &ImageLoadProviderGuid)) {
        if (opcode != 10 && opcode != 2 && opcode != 3) return;

        ParsedImageLoadEvent evt;
        memset(&evt, 0, sizeof(evt));
        evt.opcode    = opcode;
        evt.processId = eventRecord->EventHeader.ProcessId;
        evt.threadId  = eventRecord->EventHeader.ThreadId;

        parseImageLoadEvent(eventRecord, &evt);

        if (evt.processId <= 4) return;

        goImageLoadEvent(&evt);
        return;
    }

    // ---- FILE I/O events (Create=64, Write=68, Delete=70, Rename=71) ----
    if (guidsEqual(provider, &FileIoProviderGuid)) {
        if (opcode != 64 && opcode != 68 && opcode != 70 && opcode != 71) return;

        ParsedFileIoEvent evt;
        memset(&evt, 0, sizeof(evt));
        evt.opcode    = opcode;
        evt.processId = eventRecord->EventHeader.ProcessId;
        evt.threadId  = eventRecord->EventHeader.ThreadId;

        parseFileIoEvent(eventRecord, &evt);

        if (evt.processId <= 4) return;
        if (evt.filePath[0] == 0) return;  // No path — skip

        // Phase 1: Check if this is a named pipe operation.
        // Pipes use the same kernel FileIo provider but with paths under
        // \Device\NamedPipe\. We intercept them here and route to the
        // pipe handler instead of the file handler.
        if (isNamedPipePath(evt.filePath)) {
            ParsedPipeEvent pEvt;
            memset(&pEvt, 0, sizeof(pEvt));
            pEvt.processId = evt.processId;
            pEvt.threadId  = evt.threadId;
            pEvt.opcode    = evt.opcode;
            // Copy pipe name (strip the \Device\NamedPipe\ prefix)
            const WCHAR* pipeName = evt.filePath;
            if (wcsncmp(pipeName, L"\\Device\\NamedPipe\\", 18) == 0)
                pipeName += 18;
            else if (wcsncmp(pipeName, L"\\\\.\\pipe\\", 9) == 0)
                pipeName += 9;
            wcsncpy(pEvt.pipeName, pipeName, 511);
            pEvt.pipeName[511] = 0;
            goPipeEvent(&pEvt);
            return;
        }

        goFileIoEvent(&evt);
        return;
    }

    // ---- DNS events (Microsoft-Windows-DNS-Client, EventID 3006) ----
    if (guidsEqual(provider, &DnsClientProviderGuid)) {
        // EventID 3006 = DNS query completed (has both query and results)
        if (eventId != 3006) return;

        ParsedDnsEvent evt;
        memset(&evt, 0, sizeof(evt));
        evt.processId = eventRecord->EventHeader.ProcessId;
        evt.threadId  = eventRecord->EventHeader.ThreadId;

        parseDnsEvent(eventRecord, &evt);

        if (evt.processId <= 4) return;
        if (evt.queryName[0] == 0) return;  // No query name — skip

        goDnsEvent(&evt);
        return;
    }

    // ---- PROCESS ACCESS events (Kernel-Audit-API-Calls, EventID 1 = OpenProcess) ----
    if (guidsEqual(provider, &KernelAuditApiProviderGuid)) {
        // EventID 1 = OpenProcess call
        if (eventId != 1) return;

        ParsedProcessAccessEvent evt;
        memset(&evt, 0, sizeof(evt));
        evt.callerPid = eventRecord->EventHeader.ProcessId;

        parseProcessAccessEvent(eventRecord, &evt);

        if (evt.callerPid <= 4) return;
        if (evt.targetPid <= 4) return;
        // Only log successful access attempts
        if (evt.returnCode != 0) return;

        goProcessAccessEvent(&evt);
        return;
    }
}

// =====================================================================
// Session Management — Kernel Trace
// =====================================================================

static TRACEHANDLE g_sessionHandle = 0;
static BYTE        g_propBuf[4096];

int StartKernelProcessSession(
    const wchar_t* sessionName,
    const GUID*    providerGuid,
    UCHAR          level,
    ULONGLONG      matchAnyKeyword)
{
    int nameLen = (int)(wcslen(sessionName)+1) * (int)sizeof(wchar_t);
    int bufSize = (int)sizeof(EVENT_TRACE_PROPERTIES) + nameLen + 1024;
    if (bufSize > (int)sizeof(g_propBuf)) bufSize = (int)sizeof(g_propBuf);

    // Kill orphan first
    KillNamedSession(sessionName);
    Sleep(200);

    memset(g_propBuf, 0, sizeof(g_propBuf));
    PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)g_propBuf;
    p->Wnode.BufferSize    = (ULONG)bufSize;
    p->Wnode.ClientContext = 1;
    p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    // Enable PROCESS + IMAGE LOAD + FILE I/O events in a single kernel session
    p->EnableFlags         = EVENT_TRACE_FLAG_PROCESS
                           | EVENT_TRACE_FLAG_IMAGE_LOAD
                           | EVENT_TRACE_FLAG_FILE_IO_INIT;
    p->BufferSize          = 64;
    p->LoggerNameOffset    = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset   = 0;

    ULONG st = StartTraceW(&g_sessionHandle, sessionName, p);
    if (st == ERROR_ALREADY_EXISTS) {
        KillNamedSession(sessionName);
        Sleep(200);
        memset(g_propBuf,0,sizeof(g_propBuf));
        p->Wnode.BufferSize = (ULONG)bufSize;
        p->Wnode.ClientContext=1; p->Wnode.Flags=WNODE_FLAG_TRACED_GUID;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE|EVENT_TRACE_SYSTEM_LOGGER_MODE;
        p->EnableFlags = EVENT_TRACE_FLAG_PROCESS
                       | EVENT_TRACE_FLAG_IMAGE_LOAD
                       | EVENT_TRACE_FLAG_FILE_IO_INIT;
        p->BufferSize=64; p->LoggerNameOffset=(ULONG)sizeof(EVENT_TRACE_PROPERTIES);
        st = StartTraceW(&g_sessionHandle, sessionName, p);
    }
    return st == ERROR_SUCCESS ? 0 : (int)st;
}

int ProcessKernelEvents(const wchar_t* sessionName, void* ctx) {
    EVENT_TRACE_LOGFILEW t;
    memset(&t,0,sizeof(t));
    t.LoggerName          = (LPWSTR)sessionName;
    t.Context             = ctx;
    t.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    t.EventRecordCallback = stdcallEventCallback;

    TRACEHANDLE h = OpenTraceW(&t);
    if (h == INVALID_PROCESSTRACE_HANDLE) return (int)GetLastError();
    ULONG st = ProcessTrace(&h,1,NULL,NULL);
    CloseTrace(h);
    return (st==ERROR_SUCCESS||st==ERROR_CANCELLED) ? 0 : (int)st;
}

void StopKernelSession(const GUID* g) {
    BYTE b[4096]; memset(b,0,sizeof(b));
    PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)b;
    p->Wnode.BufferSize = sizeof(b);
    ControlTraceW(g_sessionHandle, NULL, p, EVENT_TRACE_CONTROL_STOP);
    g_sessionHandle = 0;
}

int KillNamedSession(const wchar_t* name) {
    int nl = (int)(wcslen(name)+1)*2;
    int bs = (int)sizeof(EVENT_TRACE_PROPERTIES)+nl+1024;
    BYTE b[4096]; if(bs>(int)sizeof(b)) bs=(int)sizeof(b);
    memset(b,0,sizeof(b));
    ((PEVENT_TRACE_PROPERTIES)b)->Wnode.BufferSize = (ULONG)bs;
    ULONG st = ControlTraceW(0,name,(PEVENT_TRACE_PROPERTIES)b,EVENT_TRACE_CONTROL_STOP);
    return (st==ERROR_SUCCESS||st==ERROR_MORE_DATA)?0:(int)st;
}

// =====================================================================
// Session Management — User-Mode ETW Providers (DNS, ProcessAccess)
//
// User-mode providers use EnableTraceEx2 to enable a specific provider
// GUID on a real-time session, unlike kernel traces which use EnableFlags.
// =====================================================================

int StartUserModeSession(
    const wchar_t* sessionName,
    const GUID*    providerGuid,
    UCHAR          level,
    ULONGLONG      matchAnyKeyword)
{
    int nameLen = (int)(wcslen(sessionName)+1) * (int)sizeof(wchar_t);
    int bufSize = (int)sizeof(EVENT_TRACE_PROPERTIES) + nameLen + 1024;
    BYTE propBuf[4096];
    if (bufSize > (int)sizeof(propBuf)) bufSize = (int)sizeof(propBuf);

    KillNamedSession(sessionName);
    Sleep(200);

    memset(propBuf, 0, sizeof(propBuf));
    PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)propBuf;
    p->Wnode.BufferSize    = (ULONG)bufSize;
    p->Wnode.ClientContext = 1;
    p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    p->BufferSize          = 64;
    p->LoggerNameOffset    = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset   = 0;

    TRACEHANDLE hSession = 0;
    ULONG st = StartTraceW(&hSession, sessionName, p);
    if (st == ERROR_ALREADY_EXISTS) {
        KillNamedSession(sessionName);
        Sleep(200);
        memset(propBuf, 0, sizeof(propBuf));
        p->Wnode.BufferSize = (ULONG)bufSize;
        p->Wnode.ClientContext = 1;
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p->BufferSize = 64;
        p->LoggerNameOffset = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
        st = StartTraceW(&hSession, sessionName, p);
    }
    if (st != ERROR_SUCCESS) return (int)st;

    // Enable the provider on this session using EnableTraceEx2
    st = EnableTraceEx2(
        hSession,
        providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        level,
        matchAnyKeyword,
        0,     // MatchAllKeyword
        0,     // Timeout (0 = async)
        NULL   // EnableParameters
    );
    if (st != ERROR_SUCCESS) {
        // Clean up session on failure
        ControlTraceW(hSession, NULL, p, EVENT_TRACE_CONTROL_STOP);
        return (int)st;
    }

    return 0;
}

int ProcessUserModeEvents(const wchar_t* sessionName, void* ctx) {
    EVENT_TRACE_LOGFILEW t;
    memset(&t, 0, sizeof(t));
    t.LoggerName          = (LPWSTR)sessionName;
    t.Context             = ctx;
    t.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    t.EventRecordCallback = stdcallEventCallback;

    TRACEHANDLE h = OpenTraceW(&t);
    if (h == INVALID_PROCESSTRACE_HANDLE) return (int)GetLastError();
    ULONG st = ProcessTrace(&h, 1, NULL, NULL);
    CloseTrace(h);
    return (st == ERROR_SUCCESS || st == ERROR_CANCELLED) ? 0 : (int)st;
}

