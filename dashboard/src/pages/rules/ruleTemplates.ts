// Starter Sigma rules for the rule editor. Each one passes the production
// quality filter (level >= medium, status test/stable, product windows) and
// its sample event uses the agent's real telemetry shape, so "Test" matches
// out of the box (each was checked against the detection engine: valid,
// loaded by the quality filter, matching its sample, not a benign event).

export interface RuleTemplate {
    key: string;
    label: string;
    yaml: string;
    sample: Record<string, unknown>;
}

export const RULE_TEMPLATES: RuleTemplate[] = [
    {
        key: 'process_creation',
        label: 'Process creation',
        yaml: `title: Encoded PowerShell command line
status: test
description: PowerShell started with a Base64-encoded command, common in droppers and loaders.
author: SOC
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_cli:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: all of selection_*
falsepositives:
  - Administrative scripts that encode their payload
level: high
tags:
  - attack.execution
  - attack.t1059.001
`,
        sample: {
            event_type: 'process',
            data: {
                executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                command_line: 'powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=',
                parent_executable: 'C:\\Windows\\System32\\cmd.exe',
            },
        },
    },
    {
        key: 'file_event',
        label: 'File creation',
        yaml: `title: Script dropped in a Startup folder
status: test
description: A script or shortcut was written to a Startup folder, so it runs at every logon.
author: SOC
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains: '\\Start Menu\\Programs\\Startup\\'
    TargetFilename|endswith:
      - '.ps1'
      - '.vbs'
      - '.bat'
      - '.cmd'
      - '.js'
  condition: selection
falsepositives:
  - Software installers adding legitimate startup items
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
`,
        sample: {
            event_type: 'file',
            data: {
                action: 'created',
                path: 'C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs',
                executable: 'C:\\Windows\\System32\\wscript.exe',
            },
        },
    },
    {
        key: 'registry_set',
        label: 'Registry value set',
        yaml: `title: Run key pointing to a user-writable folder
status: test
description: A Run/RunOnce autostart value was set to a program in AppData, Temp or Public.
author: SOC
logsource:
  product: windows
  category: registry_set
detection:
  selection_key:
    TargetObject|contains: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
  selection_path:
    Details|contains:
      - '\\AppData\\'
      - '\\Temp\\'
      - '\\Users\\Public\\'
  condition: all of selection_*
falsepositives:
  - Per-user installers such as chat or meeting clients
level: high
tags:
  - attack.persistence
  - attack.t1547.001
`,
        sample: {
            event_type: 'registry',
            data: {
                action: 'value_set',
                key_path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
                value_data: 'C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe',
                executable: 'C:\\Windows\\System32\\reg.exe',
            },
        },
    },
    {
        key: 'network_connection',
        label: 'Network connection',
        yaml: `title: Rundll32 outbound connection
status: test
description: rundll32.exe made an outbound network connection, typical of DLL-based implants.
author: SOC
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
  filter_local:
    DestinationIp|startswith:
      - '127.'
      - '10.'
      - '192.168.'
  condition: selection and not filter_local
falsepositives:
  - Control panel applets that check for updates
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011
`,
        sample: {
            event_type: 'network',
            data: {
                executable: 'C:\\Windows\\System32\\rundll32.exe',
                destination_ip: '203.0.113.50',
                destination_port: 443,
            },
        },
    },
    {
        key: 'dns_query',
        label: 'DNS query',
        yaml: `title: DNS query to a tunneling service
status: test
description: A host resolved a public tunneling domain often used for C2 and exfiltration.
author: SOC
logsource:
  product: windows
  category: dns_query
detection:
  selection:
    QueryName|endswith:
      - '.ngrok.io'
      - '.ngrok-free.app'
      - '.trycloudflare.com'
  condition: selection
falsepositives:
  - Developers exposing local services for testing
level: medium
tags:
  - attack.command_and_control
  - attack.t1572
`,
        sample: {
            event_type: 'dns',
            data: {
                query_name: 'a1b2c3.ngrok-free.app',
                executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            },
        },
    },
    {
        key: 'image_load',
        label: 'Image (DLL) load',
        yaml: `title: comsvcs.dll loaded by rundll32 (LSASS dump)
status: test
description: rundll32 loaded comsvcs.dll, whose MiniDump export is abused to dump LSASS memory.
author: SOC
logsource:
  product: windows
  category: image_load
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    ImageLoaded|endswith: '\\comsvcs.dll'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
`,
        sample: {
            event_type: 'image_load',
            data: {
                executable: 'C:\\Windows\\System32\\rundll32.exe',
                ImageLoaded: 'C:\\Windows\\System32\\comsvcs.dll',
            },
        },
    },
    {
        key: 'ps_script',
        label: 'PowerShell script block',
        yaml: `title: Offensive PowerShell toolkit in script block
status: test
description: A PowerShell script block contains function names from well-known offensive toolkits.
author: SOC
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Get-GPPPassword'
  condition: selection
falsepositives:
  - Authorized penetration tests
level: high
tags:
  - attack.execution
  - attack.t1059.001
`,
        sample: {
            event_type: 'powershell',
            data: {
                script_block_text: 'IEX (New-Object Net.WebClient).DownloadString($u); Invoke-Mimikatz -DumpCreds',
            },
        },
    },
    {
        key: 'security_eventlog',
        label: 'Windows Security log',
        yaml: `title: Local user account created
status: test
description: A user account was created (Security event 4720).
author: SOC
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  condition: selection
falsepositives:
  - Planned account provisioning by administrators
level: medium
tags:
  - attack.persistence
  - attack.t1136.001
`,
        sample: {
            event_type: 'eventlog',
            data: {
                channel: 'Security',
                EventID: 4720,
                TargetUserName: 'backdoor',
                SubjectUserName: 'alice',
            },
        },
    },
];

/** RFC 4122 v4 UUID; works outside secure contexts (plain-HTTP dashboard). */
export function newRuleId(): string {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Template YAML with a fresh `id:` so the identity is stable while editing. */
export function templateWithId(t: RuleTemplate): string {
    return `id: ${newRuleId()}\n${t.yaml}`;
}
