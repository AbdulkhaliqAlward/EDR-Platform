# Read-only diagnostics. Never invokes Atomic tests, imports a module, changes
# logging policy, stops a service, or contacts the platform/network.
[CmdletBinding()]
param(
    [string]$AtomicsPath = 'C:\AtomicRedTeam\atomics',
    [datetime]$Since = (Get-Date).AddMinutes(-30),
    [ValidateRange(1,2000)][int]$MaxEvents = 500,
    [switch]$IncludeEventText,
    [string]$OutputDirectory = (Join-Path $env:TEMP ('mitras-atomic-readiness-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists. Use a new directory to preserve earlier evidence.' }
$atomicRoot = (Resolve-Path -LiteralPath $AtomicsPath).Path
$out = New-Item -ItemType Directory -Path $OutputDirectory
$report = [ordered]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $env:COMPUTERNAME
    powershell_version = $PSVersionTable.PSVersion.ToString()
    atomics_path = $atomicRoot
    since_utc = $Since.ToUniversalTime().ToString('o')
    max_records_per_channel = $MaxEvents
    event_text_included = [bool]$IncludeEventText
    module_versions = @()
    logging_policies = @()
    channels = @()
    files = @()
}
$report.module_versions = @(Get-Module -ListAvailable Invoke-AtomicRedTeam | ForEach-Object {
    [ordered]@{version=$_.Version.ToString(); path=$_.Path}
})
$report['loaded_module_versions'] = @(Get-Module Invoke-AtomicRedTeam | ForEach-Object {
    [ordered]@{version=$_.Version.ToString(); path=$_.Path}
})
foreach ($relative in @('Indexes\index.yaml','Indexes\Indexes-CSV\windows-index.csv','T1087.001\T1087.001.yaml')) {
    $source = Join-Path $atomicRoot $relative
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        $report.files += [ordered]@{path=$relative;sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash}
        # Inert definitions/index only. No Atomic payloads are copied or executed.
        if ($relative -ne 'Indexes\index.yaml') {
            if ((Get-Item -LiteralPath $source).Length -gt 5MB) { throw "Unexpectedly large index/definition: $relative" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $out.FullName ([IO.Path]::GetFileName($relative)))
        }
    } else { $report.files += [ordered]@{path=$relative;error='missing'} }
}
foreach ($base in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore')) {
    foreach ($setting in @(@('ScriptBlockLogging','EnableScriptBlockLogging'),@('ModuleLogging','EnableModuleLogging'))) {
        $key = Join-Path $base $setting[0]
        $value = $null
        if (Test-Path -LiteralPath $key) { $value = (Get-ItemProperty -LiteralPath $key -Name $setting[1] -ErrorAction SilentlyContinue).($setting[1]) }
        $report.logging_policies += [ordered]@{key=$key;name=$setting[1];value=$value}
    }
}
foreach ($channel in @('Microsoft-Windows-PowerShell/Operational','PowerShellCore/Operational')) {
    $entry = [ordered]@{channel=$channel;records_scanned=0;may_be_truncated=$false;matching_records=@()}
    try {
        $info = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $entry['enabled'] = $info.IsEnabled
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel;Id=4103,4104;StartTime=$Since} -MaxEvents $MaxEvents -ErrorAction Stop)
        $entry.records_scanned = $events.Count
        $entry.may_be_truncated = $events.Count -eq $MaxEvents
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $fields = @{}
            foreach ($d in $xml.Event.EventData.Data) { $fields[[string]$d.Name] = [string]$d.'#text' }
            $body = [string]$fields['ScriptBlockText'] + [string]$fields['Payload']
            if ($body -notmatch '(?i)Get-Local(User|Group)|\bnet(\.exe)?\s+(user|localgroup)|cmdkey(\.exe)?\s+/list') { continue }
            $record = [ordered]@{id=$event.Id;record_id=$event.RecordId;time_utc=$event.TimeCreated.ToUniversalTime().ToString('o');pid=[string]$xml.Event.System.Execution.ProcessID;script_block_id=$fields['ScriptBlockId']}
            if ($IncludeEventText) { $record['event_data']=$fields }
            $entry.matching_records += $record
        }
    } catch { $entry['query_error'] = $_.Exception.Message }
    $report.channels += $entry
}
# ── Agent event-log forwarding readiness (read-only) ──────────────────────────
# The agent forwards selected Security/System/Defender records and enables the
# audit subcategories they need. This only reads the resulting state.
$agentLog = [ordered]@{ service = $null; audit_subcategories = @(); enabled_by_agent = $null; channels = @(); bookmarks = @() }
try { $svc = Get-Service -Name EDRAgent -ErrorAction Stop; $agentLog.service = [ordered]@{status=[string]$svc.Status; start_type=[string]$svc.StartType} } catch { $agentLog.service = 'not installed' }
$subcategories = [ordered]@{
    'Security System Extension (4697)'        = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events (4698-4702)'  = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'User Account Management (4720-4726)'     = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management (4728/4732)'   = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change (4719)'              = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Logon (4624/4625/4648)'                  = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Credential Validation (4776)'            = '{0CCE923F-69AE-11D9-BED3-505054503030}'
}
foreach ($name in $subcategories.Keys) {
    $row = [ordered]@{subcategory=$name; guid=$subcategories[$name]}
    try {
        $csv = (& auditpol.exe /get /subcategory:$($subcategories[$name]) /r) | Where-Object { $_ } | ConvertFrom-Csv
        $row['setting'] = ($csv | Select-Object -First 1).'Inclusion Setting'
    } catch { $row['error'] = $_.Exception.Message }
    $agentLog.audit_subcategories += $row
}
try { $agentLog.enabled_by_agent = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\EDR\Agent' -Name AuditPolicyEnabledByAgent -ErrorAction Stop).AuditPolicyEnabledByAgent } catch { $agentLog.enabled_by_agent = $null }
$forwarded = [ordered]@{
    'Security' = @(4697,4698,4702,4720,4726,4732,4719,1102,4625,4648)
    'System' = @(7045,7040,104)
    'Microsoft-Windows-Windows Defender/Operational' = @(1116,1117,5001,5007,5010,5012,5013)
    'Microsoft-Windows-TaskScheduler/Operational' = @(106,129,140,141)
}
foreach ($channel in $forwarded.Keys) {
    $row = [ordered]@{channel=$channel}
    try {
        $info = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $row['enabled'] = $info.IsEnabled; $row['record_count'] = $info.RecordCount
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel;Id=$forwarded[$channel];StartTime=$Since} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        $row['records_since'] = $events.Count
        $row['ids_seen'] = @($events | Group-Object Id | ForEach-Object { [ordered]@{id=[int]$_.Name; count=$_.Count} })
    } catch { $row['error'] = $_.Exception.Message }
    $agentLog.channels += $row
}
$stateDir = 'C:\ProgramData\EDR\state'
if (Test-Path -LiteralPath $stateDir) {
    $agentLog.bookmarks = @(Get-ChildItem -LiteralPath $stateDir -Filter 'evt_bookmark_*.xml' -ErrorAction SilentlyContinue |
        ForEach-Object { [ordered]@{file=$_.Name; last_write_utc=$_.LastWriteTimeUtc.ToString('o')} })
}
$report['agent_eventlog'] = $agentLog

$executionLog = Join-Path $env:TEMP 'Invoke-AtomicTest-ExecutionLog.csv'
if (Test-Path -LiteralPath $executionLog) {
    # Full GUIDs and times (the console table truncates them).
    $report['recent_execution_log'] = @(Import-Csv -LiteralPath $executionLog | Select-Object -Last 50 |
        Select-Object 'Execution Time (UTC)', Technique, 'Test Number', 'Test Name', GUID, Username)
}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out.FullName 'readiness.json') -Encoding UTF8
Write-Output "Read-only diagnostics saved to $($out.FullName). Nothing was uploaded. Review the files before sharing."
