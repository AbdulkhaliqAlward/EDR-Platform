# T1087.001 discovery integration — 2026-10-10

Baseline: clean `Main` / `f4db096f`; earlier Atomic/branding work was already committed by the user. Work remains local and undeployed. This document supersedes the earlier unknown-library-path note; it does not claim all Atomic tests are covered.

## User evidence and what it proves

- Endpoint installation: `C:\AtomicRedTeam\atomics`; 344 technique directories; approximate directory creation 2026-10-03. This directory is on the user's endpoint and is **not present** on the coding host.
- Supplied `Indexes/index.yaml` SHA-256 `08F8BD071D96261E12E520A8BBA4EF85DF33E611491F2435671D4F8FE94C49A4` exactly matches the pinned official source revision `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` downloaded read-only during this task. This verifies index identity, not the payloads or installed agent binary.
- `Get-Module -ListAvailable` lists Invoke-AtomicRedTeam 2.3.0; the separate bundled manifest says 2.1.0. Those can coexist. Neither proves which module was loaded for the logged executions.
- Execution log identifies T1087.001 tests 8 and 9. Official GUIDs: `80887bec-5a9b-4efc-a81d-f83eb2eb32ab` (command prompt), `ae4b6361-b5f8-46cb-a3f9-9cf108ccfe7b` (PowerShell). Relevant behavior includes `net user`, `net localgroup`, `Get-LocalUser` and `Get-LocalGroupMember`. The runner log alone does not prove successful prerequisites, event collection, receipt by the server or detection.
- Asked whether these events are visible in the platform Events page; the user answered that they have not checked yet. The original live detection miss remains unlocalized. Existing rules already matched some of this behavior, so absent telemetry/deployment/runtime state cannot be assumed fixed just by adding rules.

## Changes and integration points

| Requirement | Implementation | Verification/status |
|---|---|---|
| Classify local discovery without requiring a particular parent | Three rules in `sigma_engine_go/sigma_rules/rules/edr_custom/mitras_{proc,ps,pm}_local_account_discovery.yml` | Positive/negative fixtures for process creation, 4104 script and 4103 module evidence |
| Keep account reads distinct from changes | New rules tag T1087.001/T1069.001 and medium severity; process query rule rejects /add, /delete and /domain | Verified for new rules; legacy third-party `posh_ps_localuser.yml` remains unchanged and can additionally match Get-LocalUser as T1098; existing/operator rules require runtime tuning |
| Preserve actual collector output | `TestPowerShellLocalDiscoveryEvidence` exercises actual XML parsing/handoff with synthetic 4103/4104 XML | Type, action, content, event code and original timestamp checked; no live subscription |
| Deliver matched evidence before source acknowledgement | `TestLocalDiscoveryDurableDelivery` uses the three shipped rules and real detection worker with blocked fake persistence/broker | No acknowledgement before persistence and broker confirmation; canonical alert ID preserved |
| Appropriate automatic response | CM migration `063_local_discovery_investigation` creates an investigation playbook and exact-rule policy | Collection only; server automation switch, online endpoint, per-endpoint coordination and 30-minute cooldown apply |
| Bound collection requests | `connection-manager/internal/response/context.go` now exposes and preserves `max_events` and `time_range` for log collection | A regression test first reproduced the old loss of both parameters, then passed after the fix. Invalid bounds are rejected |
| Respect collection scope and cancellation | Agent `internal/command/handler.go` reads newest events first, no longer falls back to an unfiltered log on query failure, and derives the PowerShell helper timeout from the command context | Cancelled-context test proves no helper process starts; query behavior needs live validation |
| Diagnose deployed telemetry without running attacks | `scripts/Collect-AtomicReadiness.ps1` | Syntax checked; not run on the user's endpoint |

Rule IDs, in process/script/module order:

- `9f8f4f57-6d7e-4d23-a60a-319f7c36910a`
- `bcc784ca-8489-4b37-938b-b0929df6b996`
- `2b39a76c-d927-443d-93ac-2e8c0770b8cb`

The built-in playbook ID is `1e13819d-8d38-44e9-8f74-8ab945e85835`; automation rule ID is `56956211-fd47-49a1-ad67-7d6586e7d61a`. It requests at most 200 events **per channel** for the prior 15 minutes from Security, Windows PowerShell and PowerShell Core, with a 60-second command timeout. Missing channels/errors remain visible in the collection result; absent audit logging cannot be retroactively created. Existing channel-enablement behavior in the agent collection handler is unchanged. It does not terminate processes or isolate endpoints.

Migration 063 inserts only absent IDs (`ON CONFLICT DO NOTHING`) and does not overwrite operator changes. Rollback disables this policy/playbook while retaining referenced records/history. It is applied by the normal CM migration startup on deployment, not by this coding session. The global server automation switch is not enabled by this migration. Existing claimed alerts are not replayed as new actions.

## Verification and remaining work

- Sigma full detection, Kafka and handlers packages passed. Targeted tests cover the three new rules through the real detection worker, including durable acknowledgement ordering. Final Sigma build passed.
- CM full response and server packages passed; response vet and server build passed. Policy tests read the actual migration JSON, verify every seeded rule ID, no dispatch for an unrelated rule/disabled automation, replay idempotence, command type and preserved collection bounds.
- Migration 063 was applied twice against a disposable loopback PostgreSQL 17 database using the repository migration fixtures. Verified seeded values, preservation of an operator-disabled policy and cooldown, and rollback retaining/disabling the playbook. The first attempt failed to connect because the local test harness waited on the PostgreSQL process tree; the launcher was corrected and the test passed. The disposable cluster was shut down. No deployed DB was accessed.
- Agent pure collector parsing/reassembly/local-discovery tests and command collection/cancellation tests passed. Final Windows/CGO agent build passed. No Atomic payload or endpoint command was executed. Built binaries are not run.
- The latest inventory contains 2,183 eligible compilable disk rules with no parse/compile rejection. Candidate counts remain 1,085 exact-technique, 60 parent-only and 108 without a tagged candidate across 1,253 unique Windows tests. These are **not** per-test coverage or response-success counts.

Deployment/validation order:

1. Deploy updated Sigma, CM (including migration 063), and agent. Verify the three new detection IDs and the investigation policy in the runtime UI/DB; disk presence alone is not runtime activation. Existing DB overrides and exceptions are preserved.
2. On the endpoint, start a **new PowerShell session** after script-block logging is enabled. [Microsoft documents that newly started sessions record the enabled logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1). The module rule is supplementary: module logging must separately exist for 4103 records.
3. Run `powershell -File .\scripts\Collect-AtomicReadiness.ps1` from the deployed repository for metadata only; add `-IncludeEventText` to include relevant script/module evidence locally. Adjust `-Since` to the user's test time. The script collects up to the requested number of recent records per channel, reports possible truncation, copies only the Windows index and T1087.001 definition, and never runs/imports Atomic commands or uploads the output.
4. User-owned isolated test: correlate the test GUID/time to the endpoint event record, server Events entry, matched rule, persisted alert, UI notification and response execution result. Check the execution's per-step result rather than assuming an alert implies completed collection. A second detection within the policy's cooldown deliberately does not collect again.
5. Remaining **unverified**: actual deployed event arrival, broker/database outages/rebalances under load, UI timing on this endpoint, successful remote collection, and all other Atomic test paths. The new fixes are verified in isolated software tests; full deployed end-to-end operation and universal malicious-event coverage are not claimed.
