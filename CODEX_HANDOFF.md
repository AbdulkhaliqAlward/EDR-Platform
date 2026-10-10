# Detection and Response Engine recovery

Recovered on 2026-10-08 (Asia/Riyadh), before implementation changes by Codex.

## Evidence and repository state

- Branch: `Main`; HEAD: `5a089cfa1602c3792adb74fd146d9a58385026e9` (`feat(automation): add server-side playbook execution engine and alert context binding`).
- No staged changes. Extensive existing unstaged edits and required untracked files are listed below. No reset, stash, clean, commit, or checkout performed.
- No `AGENTS.md`, `CLAUDE.md`, or earlier `CODEX_HANDOFF.md` found in the repository or inspected parent directories.
- `CLAUDE_CONTEXT.md` is a user-supplied conversation capture. Historical instructions and test claims in it are evidence of intent, not fresh authorization or independently verified results. Its final recorded action is reading `AutomationRulesPage.tsx` imports/reset helper; the limit interrupted implementation of the server switch UI and exact rule/MITRE trigger fields.
- `context_handoff.md` describes older tasks/toolchain constraints; its Git/task state is stale relative to HEAD. Root README contains unrelated deployment material and sensitive values: do not copy it into handoff artifacts. Memory feedback asks for focused, code-verified changes and build/vet/tests; it does not establish prior results.
- Existing changes strongly resemble the conversation capture, but individual authorship is unknown. Preserve all existing edits, including deletions that replace older helpers.

## Requirements mapped to current code (initial recovery)

Statuses below mean code inspection only. No test has yet been executed by Codex. Claude's statements that builds/tests passed are unverified historical claims; the capture usually omits exact commands/results.

| Requirement and acceptance | Current paths/symbols | Recovered status / remaining verification |
| --- | --- | --- |
| Coordinate manual/automatic response per endpoint; expose queued/running/results without contradictory actions | CM `internal/response/engine.go`: `Start`, `lockAgent`, `ActiveOn`, `execute`, `runStep`; `repository/response_engine_repo.go`; migration 060; dashboard `PlaybookRunPanel`, `AlertResponseHistory`, `ResponseActivityBell` | Partially implemented. In-process endpoint lock only covers this response engine. Review direct commands, legacy post-isolation engine, replica behavior, settings changes while queued, and persistence races. |
| Idempotent isolation and continued C2 commands while isolated | CM `runStep`; agent `command/handler.go`: `isolateNetwork`; CM `pkg/server/server.go`, `pkg/playbook/engine.go` triage dedup | Implemented but unverified. Firewall/C2 behavior requires disposable endpoint. Re-isolation cutting streams is a plausible explanation from the capture, not reproduced here. |
| Manual process vs tree selection; automatic tree termination; identity and complete results | CM `response/context.go`: `BuildAlertVars`, action catalog; agent `command/terminate_windows.go`; dashboard `PlaybookRunPanel` | Implemented but unverified. Test PID reuse, stale identity, exited parent/orphans, partial failures, newly spawned descendants and default kill scope. Existing Windows tests include real process termination; do not execute them on the user's host. |
| Global server automation toggle; hide alert automatic-response control when off | CM `response/settings.go`, `trigger.go`, `api/handlers_response.go`; dashboard `hooks/useAutomationSettings.ts`, `AlertDetailPanel` | Partially implemented. Settings API exists, Automation Rules page switch missing. Verify authoritative enforcement for pending runs, env lock, read failures, RBAC/audit, and disabled-period replay. Local agent prevention is a separate existing path, not controlled by this server toggle. |
| Safe structured response triggers with exact Sigma IDs and MITRE techniques | CM `response/conditions.go`: `ParseConditions`, `Matches`, `ScopedForContainment`, `ContainmentAllowedFor`; API `handlers_automation.go` | Partially implemented. Dashboard only supports severity/title/minimum risk, loses new fields when editing. Runtime guardrail and validation require regression tests. |
| Reduce false positives without AI or broad security bypass | Sigma `detection/exceptions.go`, database `exception_repo.go`, migration 018; CM exceptions repo/API; dashboard exceptions page/modal | Implemented but unverified. Verify same field resolution, expiry/scope/operators, RBAC/audit, database migration ownership and refresh/hit counts. No representative FP corpus supplied. |
| Accurate severity, bounded risk/context bonuses and understandable evidence | Sigma `alert/alert_generator.go`: `calculateAggregatedSeverity`; `scoring/risk_scorer.go`, `burst_tracker.go`; dashboard `AlertEvidencePanel`, `UEBAPanel` | Implemented but unverified. Highest rule level preserved, distinct-rule burst and privilege/LOLBIN changes present. No universal score/response threshold is established by a standard; these are local policies requiring calibration. |
| Correct behavioral baseline units and event time | Sigma `baselines/baseline_{aggregator,cache,repository}.go`; migration 019; scoring `computeUEBA`; main wiring | Implemented but unverified. Hourly process executions replace EMA; inspect retention, learning, same-hour baselines, zero buckets, flush/retry and sparse hosts. |
| PowerShell commands/script blocks through event→Sigma→alert→UI | Agent `collectors/powershell_windows.go`, `pslogging/`, agent config/start/uninstall; Sigma event/category/mapper additions | Implemented but unverified. Validate 4104 fragments, 4103, Windows PowerShell/Core channels, bookmarks/backpressure and policy restore. Isolated Windows verification required for logging-policy changes. |
| Phase 4 process telemetry, bounded work/rate limiting and drop metrics | Agent `collectors/process_pipeline_windows.go`, `etw.go`, collector self-PID checks, `agent.go` | Implemented but unverified. Verify process lineage/path/metadata, worker pool shutdown, detection-critical exemptions and counters. Full CGO build unavailable until a C compiler is found. |
| Phase 5 signature trust (embedded/catalog Authenticode, signer/hash/PE identity) | Agent `collectors/file_identity_windows.go`, `imageload.go`, process pipeline; Sigma signer/LOLBIN scoring | Implemented but unverified. Validate trusted/untrusted/catalog/unsigned/tampered files and cache invalidation in isolated Windows environment. |
| Any additional formal Phase 4/5 acceptance criteria | Capture references phases but no complete phase specification is included | Unknown due to missing context. Do not infer from unrelated older Sigma `Docs/PHASE*` reports. |

## Implementation flow and integration points

1. Windows collectors emit agent `event.Event` into `eventChan`. Process ETW callbacks feed bounded enrichment workers; PowerShell Windows Event Log subscriptions emit `powershell` records. `agent.go` batcher applies rate limits, queues durable batches and sends gRPC telemetry.
2. CM event ingestion validates agent identity, normalizes payloads and publishes to Kafka; Sigma Kafka consumer invokes the detection pipeline. `field_mapper.go` and event category inference route rule evaluation. `detection_engine.go:matchRule` checks analyst exceptions after matches using Sigma field resolution.
3. Sigma baseline aggregator records process executions; risk scorer combines rule/context signals; alert generator persists matched fields/context/severity/risk to `sigma_alerts`. Sigma owns migrations 018/019 and the exceptions table; CM manages exception CRUD through its authenticated/RBAC API against the shared database.
4. CM response trigger claims new Sigma alerts through inbox/state tables, evaluates enabled auto-execute rules, cooldown and guardrails, prepares alert-bound steps and records `playbook_executions`. `Start` queues per endpoint, executes sequential steps, creates persistent commands, dispatches through `AgentRegistry` and polls command results. Migration 060 adds analyst-facing execution context.
5. Agent command handler performs actions and returns results over gRPC. CM updates commands/isolation state; the separate legacy post-isolation playbook engine may dispatch triage commands. Dashboard APIs query settings, exceptions, execution history and raw autonomous prevention events; alert evidence renders original event fields.
6. Important boundaries: CM server settings do not disable agent local prevention; in-memory response locks are not distributed locks and do not serialize every raw command path. Investigate before claiming all-response coordination.

## Known stopping point / uncertainties

- Exact next feature: finish `dashboard/src/pages/automation/AutomationRulesPage.tsx` switch and fields for `rule_ids` / `mitre_techniques`, preserving supported `logic_operator` when editing.
- No temporary stub discovered yet. Capture says prior CGO type-check stub was removed. Agent CGO files are excluded with CGO disabled, so that cannot prove production ETW build validity.
- Historical hypothesis that sequential triage alone caused the wait was revised in the capture after discovering agent concurrency. Do not repeat it as established root cause.
- Existing tests that terminate child processes or touch host logging must use an isolated Windows environment or be replaced by pure/mocked checks for this session.
- No running deployment, seeded integration database, event fixture corpus or disposable Windows VM is established. End-to-end and performance/security field verification remain open.

## Ordered continuation plan

1. Preserve baseline binary Git diffs and the required-untracked inventory after checking for credential material; do not overwrite an existing artifact.
2. Run targeted baseline CM response/API/playbook and Sigma detection/scoring/baseline/domain tests; compile dashboard; run pure agent tests only. Record actual commands/results and tooling constraints.
3. Complete Automation Rules UI against actual API shape: load/refresh server state, reasoned audited switch, env-lock/error handling, exact IDs/MITRE conditions, accurate summary/edit/preview. Verify via build and mocked browser/API interactions.
4. Follow failures/root causes through integrations. Add focused tests for automatic-tree defaults, setting enforcement on queued work, closed-alert reevaluation, response identity/persistence/coordination, exception matching, telemetry/category/scoring contracts. Fix defects in dependency order.
5. Verify migrations and server API behavior against an isolated PostgreSQL fixture if available; verify Kafka→alert→response with mock command delivery. Do not run production deployment or endpoint actions.
6. Complete isolated CGO Windows build, Authenticode/PowerShell collection, firewall/C2 and real tree-termination checks when tooling/environment is available. Record every blocked/unverified requirement explicitly; do not claim E2E completion.

## Setup and verification record

- Host context: Windows/PowerShell; dashboard has `node_modules`. Modules: CM/Sigma Go 1.24.0; agent Go 1.24. Root module is unrelated `wmitest` Go 1.25.5: execute module commands from their own directories.
- Historical toolchain path: `%TEMP%/edr-fix/go/bin/go.exe`. Use `GOTOOLCHAIN=local` to avoid unrelated root-module automatic downloads. CGO production ETW requires a suitable Windows C compiler, not a fake collector.
- Relevant environment names (no values): `AUTOMATION_AUTO_EXECUTE`, `C2_GRPC_ADDRESS`, `EDR_ALLOW_CUSTOM_COMMANDS`, database/Kafka/Redis configuration from compose/config.
- Commands/results from Codex will be appended below. Initial recovery has only read-only Git/source inspection.

## Baseline inventory (before Codex implementation)

```text
 M connection-manager/cmd/server/main.go
 M connection-manager/internal/repository/response_engine_repo.go
 M connection-manager/internal/response/conditions.go
 M connection-manager/internal/response/context.go
 M connection-manager/internal/response/engine.go
 M connection-manager/internal/response/response_test.go
 M connection-manager/internal/response/trigger.go
 M connection-manager/internal/response/validate.go
 M connection-manager/pkg/api/handlers_automation.go
 M connection-manager/pkg/api/handlers_response.go
 M connection-manager/pkg/api/middleware.go
 M connection-manager/pkg/api/server.go
 M connection-manager/pkg/playbook/engine.go
 M connection-manager/pkg/server/server.go
 M dashboard/nginx.conf
 M dashboard/src/App.tsx
 M dashboard/src/api/client.ts
 M dashboard/src/components/alerts/AlertDetailPanel.tsx
 M dashboard/src/components/alerts/UEBAPanel.tsx
 M dashboard/src/components/automation/PlaybookRunPanel.tsx
 M dashboard/src/layout/PlatformAppShell.tsx
 M dashboard/src/layout/PlatformNavConfig.ts
 M sigma_engine_go/cmd/sigma-engine-kafka/main.go
 M sigma_engine_go/internal/application/alert/alert_generator.go
 M sigma_engine_go/internal/application/baselines/baseline_aggregator.go
 M sigma_engine_go/internal/application/baselines/baseline_cache.go
 M sigma_engine_go/internal/application/baselines/baseline_repository.go
 M sigma_engine_go/internal/application/baselines/baseline_test.go
 M sigma_engine_go/internal/application/detection/agent_self_filter.go
 M sigma_engine_go/internal/application/detection/agent_self_filter_test.go
 M sigma_engine_go/internal/application/detection/detection_engine.go
 M sigma_engine_go/internal/application/mapping/field_mapper.go
 M sigma_engine_go/internal/application/scoring/burst_tracker.go
 M sigma_engine_go/internal/application/scoring/context_snapshot.go
 M sigma_engine_go/internal/application/scoring/risk_scorer.go
 M sigma_engine_go/internal/application/scoring/risk_scorer_test.go
 M sigma_engine_go/internal/domain/event.go
 M sigma_engine_go/internal/domain/event_category.go
 M win_edrAgent/internal/agent/agent.go
 M win_edrAgent/internal/agent/agent_windows.go
 M win_edrAgent/internal/collectors/dns.go
 M win_edrAgent/internal/collectors/etw.go
 M win_edrAgent/internal/collectors/file.go
 M win_edrAgent/internal/collectors/imageload.go
 M win_edrAgent/internal/collectors/network.go
 M win_edrAgent/internal/collectors/pipe.go
 M win_edrAgent/internal/collectors/process_access.go
 D win_edrAgent/internal/collectors/signature_status_windows.go
 M win_edrAgent/internal/collectors/wmi.go
 M win_edrAgent/internal/command/handler.go
 D win_edrAgent/internal/command/proctree_stub.go
 D win_edrAgent/internal/command/proctree_windows.go
 M win_edrAgent/internal/command/uninstall_cleanup.go
 M win_edrAgent/internal/command/uninstall_offline.go
 M win_edrAgent/internal/config/config.go
 M win_edrAgent/internal/event/types.go
?? CLAUDE_CONTEXT.md
?? connection-manager/internal/database/migrations/060_response_coordination.down.sql
?? connection-manager/internal/database/migrations/060_response_coordination.up.sql
?? connection-manager/internal/repository/detection_exception_repo.go
?? connection-manager/internal/response/coordination_test.go
?? connection-manager/internal/response/settings.go
?? connection-manager/pkg/api/handlers_exceptions.go
?? connection-manager/pkg/api/handlers_exceptions_test.go
?? dashboard/src/components/alerts/AlertEvidencePanel.tsx
?? dashboard/src/components/alerts/CreateExceptionModal.tsx
?? dashboard/src/components/automation/AlertResponseHistory.tsx
?? dashboard/src/components/automation/ResponseActivityBell.tsx
?? dashboard/src/hooks/useAutomationSettings.ts
?? dashboard/src/pages/automation/DetectionExceptionsPage.tsx
?? sigma_engine_go/internal/application/detection/exceptions.go
?? sigma_engine_go/internal/application/detection/exceptions_test.go
?? sigma_engine_go/internal/domain/powershell_category_test.go
?? sigma_engine_go/internal/infrastructure/database/exception_repo.go
?? sigma_engine_go/internal/infrastructure/database/migrations/018_detection_exceptions.down.sql
?? sigma_engine_go/internal/infrastructure/database/migrations/018_detection_exceptions.up.sql
?? sigma_engine_go/internal/infrastructure/database/migrations/019_process_activity_hourly.down.sql
?? sigma_engine_go/internal/infrastructure/database/migrations/019_process_activity_hourly.up.sql
?? win_edrAgent/internal/collectors/file_identity_windows.go
?? win_edrAgent/internal/collectors/powershell_windows.go
?? win_edrAgent/internal/collectors/powershell_windows_test.go
?? win_edrAgent/internal/collectors/process_pipeline_windows.go
?? win_edrAgent/internal/collectors/process_pipeline_windows_test.go
?? win_edrAgent/internal/command/terminate_windows.go
?? win_edrAgent/internal/command/terminate_windows_test.go
?? win_edrAgent/internal/pslogging/pslogging_windows.go
```

- CODEX_HANDOFF_UNSTAGED.patch: saved (228726 bytes); heuristic credential scan found no suspect literals
- CODEX_HANDOFF_STAGED.patch: saved (0 bytes); heuristic credential scan found no suspect literals
- `CODEX_HANDOFF_UNTRACKED.txt` lists files patches cannot preserve. It excludes handoff artifacts and contains paths only. Transfer files separately, reviewing sensitive content securely.

## Codex continuation results (authoritative latest state)

The initial recovery table above is historical. This section supersedes its "unverified" labels only to the extent demonstrated below. Branch/HEAD are unchanged, nothing is staged or committed, and every baseline required untracked file is still present.

### Recovered phase scope and constraints

Project memory `project-edr-platform-context.md` identifies Phase 4 as agent filtering/self ancestry, trusted paths, bounded ETW workers, drop counters and rate limiting; Phase 5 as baseline units/event time/signature trust. It also records an earlier user refusal to change `sigma_engine_go/config/config.yaml`; Codex did not change that configuration. The older backlog mentions rule DB-to-running-engine synchronization and `related_rule_ids`; these were not implemented in this continuation, and their full current status was not audited. Do not treat older phase-completion reports as current acceptance evidence.

### Changes made by Codex and supporting evidence

- `dashboard/src/pages/automation/AutomationRulesPage.tsx`: completed the missing server automation switch (effective state, admin-only UI, reason, configuration lock and errors), exact rule IDs/MITRE fields, AND/OR preservation, alert prefill, accurate summaries and removal of the stale "not enabled on server yet" message. `AlertDetailPanel.tsx` passes rule identity and techniques in navigation context. Mock UI requests verified PUT settings and PATCH rule payloads preserve `rule_ids`, `mitre_techniques`, `logic_operator`.
- `connection-manager/internal/response/engine.go:Prepare`: automation forces `kill_tree=true` and refuses termination lacking measured process image/start time. Manual scope remains selectable. `context.go:BuildAlertVars` no longer substitutes collection time for measured creation time.
- `engine.go:Start`, `automaticRunAllowed`, `execute`: automation is checked at admission, after endpoint/global queuing and before undispatched steps. Disabling automation or closing the alert cancels queued automatic work; already dispatched actions may finish. Returned records/step arrays are independent snapshots, avoiding asynchronous mutation during API JSON encoding.
- `response/settings.go:AutomationSettings`: corrupt stored JSON fails closed. `trigger.go:processAlert` applies scope guardrails at runtime as well as at rule-save time; legacy broad conditions cannot drive containment solely because an alert is High/Critical.
- `pkg/playbook/engine.go:SetAutomationGate`, `cmd/server/main.go`: the legacy post-isolation triage path now checks the same effective server switch before starting and between dispatches. A disabled/unavailable response engine disables that automatic path. This does not merge its execution/history/locking into the new response engine.
- `pkg/api/handlers_agents.go:SendCommand`: removed optimistic isolation state updates at dispatch. Previously, a failed raw command could leave `is_isolated=true`, causing `response.runStep` to skip necessary containment. State is now updated by successful command result/heartbeat. This source path is compiled and API package tests pass; the failure scenario has not been exercised against a live endpoint.
- `repository/response_engine_repo.go:ListExecutions`, `api/handlers_response.go`, dashboard client and `ResponseActivityBell`: notification windows now support upper bounds and ascending `(updated_at,id)` keyset cursors. The bell drains saturated windows across bounded polling batches, keeps separate progress for executions/events, retains cursors on failures, prevents overlapping polls and caps dedup memory. SQL and notification-volume behavior still require live/mocked integration verification beyond compilation. Delayed agent prevention events older than a completed event-time window may still need an ingestion-time feed.
- `AlertResponseHistory.tsx`: continues polling when initially empty or all runs are terminal, so automation starting after the panel opens appears. Retries failed loads. Evidence panel distinguishes reassembled/truncated source content.
- `win_edrAgent/internal/command/terminate_windows.go`: validates exact measured creation time even for a reused PID with the same image; refuses unqueryable identity instead of comparing a bare filename; checks the same handle before suspension/termination; excludes children of reused live anchors; reports snapshot/residual/unknown-child failures. Crucial limitation: if the root exited BEFORE the request, it refuses orphan attribution and reports tree completion unverified. A mere parent PID and lower start-time bound do not prove ancestry after multiple PID generations. Orphans of processes observed and terminated DURING this operation remain supported.
- `collectors/powershell_reassembly_windows.go` and `powershell_windows.go`: bounded 4104 fragment reassembly (64 assemblies, 64 parts, 512 KiB per assembly, 2-minute expiry); individual fragments remain visible, and final completed script can match across fragments. Preserves original event timestamp, and enriches PID/image/start only when a current process existed at that event time. Incomplete/oversized scripts still have a visibility limit; no unlimited-content claim is made.
- `collectors/process_pipeline_windows.go`: measured creation-time provenance is explicit; fallback callback times are not published as measured process identity. Process-table reads return snapshots under lock instead of pointers mutated by exit updates.
- `sigma_engine_go/internal/application/baselines/baseline_repository.go`: first-seen history excludes the current/future hour, preventing a current-hour flush from turning new activity into historical activity. Existing hourly statistics/scoring changes passed targeted tests. Current observed counts are in-memory and reset on service restart; restart/replay behavior still needs integration/calibration.
- New regression files: CM `pkg/playbook/automation_gate_test.go`; Sigma `application/alert/severity_test.go`; new cases in coordination/termination/PowerShell/baseline tests. Existing work was preserved. A package-wide gofmt briefly changed five unrelated command files; their original bytes were reconstructed from HEAD plus the saved baseline patch and restored after comparing exact gofmt output. No pre-existing semantic edits were discarded.

### Latest requirement status

| Requirement | Latest supported status |
| --- | --- |
| Automation Rules switch and exact ID/MITRE condition UI | Implemented and verified by build/lint and isolated mock browser save/toggle; real auth/OTP/audit persistence unverified |
| Server setting, queue cancellation, closed-alert verdicts, containment guardrails, automatic tree default | Implemented and verified with fake stores/command delivery; live DB/C2 integration unverified |
| Manual/automatic playbook serialization inside the new CM response engine | Implemented and verified with simulated delivery; direct raw commands, legacy triage, replicas and agent-local prevention are not all serialized by this lock |
| Analyst response history and notification polling | Implemented; build/lint and some mock UI verified. Saturation/outage/late-arrival feed integration remains unverified |
| Isolation idempotency and commands while isolated | Implemented in recovered agent/server code; compiled/response no-op unit behavior verified. Real firewall/C2 remains unverified |
| Process-only and live-root tree response | Implemented; pure ancestry/identity checks verified. Real suspension/termination remains unverified |
| Tree response after root exited before dispatch | Partially implemented: safely reports unverified and does not guess orphan ownership. Requires retained lineage and isolated tests |
| Detection exceptions | Recovered implementation verified by detection/API validation tests. DB CRUD/RBAC/approval/audit/refresh across services unverified |
| Severity/risk/UEBA correctness | Rule-level preservation, risk tests and baseline unit behavior verified. Production FP calibration, Redis-backed distinct-rule behavior, restart rates and PG statistics unverified |
| PowerShell script visibility and mapping | Parsing, event timestamp, fragment assembly/category unit behavior verified; live policy/bookmarks/4103/Core/cross-fragment Sigma→UI remain unverified |
| Phase 4 process filtering/identity/worker/rate/drop behavior | Non-CGO enrichment/filter/rate/parent/self tests verified in a temporary copy. Production CGO session, overload and shutdown remain unverified |
| Phase 5 Authenticode/hash/PE enrichment | Microsoft/unsigned/tampered file identity tests passed in the temporary non-CGO collector copy; broader catalog/cache/revocation/production behavior unverified |
| Older DB rule synchronization / related rule IDs backlog | Not implemented in this continuation; missing full acceptance context |

### Actual commands and results

Host: Windows/PowerShell, Node v24.18.0, npm 11.16.0. All successful final Go checks used the genuine downloaded `C:/Users/onyxv/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.5.windows-amd64/bin/go.exe`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, from the module directories. Do not use the root `wmitest` module to test these services.

| Working directory / command | Actual result and scope |
| --- | --- |
| CM: `go test ./internal/response ./pkg/api ./pkg/playbook ./internal/repository` (baseline) | Passed; repository initially had no tests. Response/API mocks and validators, no live services |
| Sigma: `go test ./internal/application/detection ./internal/application/scoring ./internal/application/baselines ./internal/application/alert ./internal/application/mapping ./internal/domain ./internal/infrastructure/database` (initial old-toolchain attempt) | Detection/domain passed; alert/mapping initially had no tests. Scoring/baselines/database failed setup: `package crypto/pbkdf2 is not in std` in the old temp toolchain |
| Sigma, genuine toolchain: `go test ./internal/application/scoring ./internal/application/baselines ./internal/infrastructure/database` | Passed after fixing toolchain, without rerunning successful detection/domain checks |
| CM after semantic changes: `go test ./internal/response ./pkg/api ./pkg/playbook` | Passed, including queue/switch/closed-verdict/tree-default/missing-identity/snapshot/guardrail regressions |
| CM after raw isolation API change: `go test ./pkg/api` | Passed |
| CM: `go vet ./internal/response ./pkg/api ./pkg/playbook ./internal/repository ./pkg/server` | Failed on pre-existing `internal/repository/crl_cache.go:106`: copying `sync.Map` containing `sync.noCopy`. No change made to CRL cache |
| CM: `go vet ./internal/response ./pkg/api ./pkg/playbook ./pkg/server` and `go build -o %TEMP%/codex-edr-cm-server.exe ./cmd/server` | Passed. Full repository vet remains a known failure |
| Sigma after baseline/alert changes: `go test ./internal/application/baselines ./internal/application/alert` | Passed, including current-hour first-seen and overlapping High-rule severity regressions |
| Sigma: `go vet ./internal/application/baselines ./internal/application/scoring ./internal/application/alert ./internal/application/detection ./internal/application/mapping ./internal/domain`; `go build ./cmd/sigma-engine-kafka` | Passed; compiler only, no service started |
| Agent command: `go test ./internal/command -run 'TestCollectDescendants|TestDescendantsExclude|TestSameImage|TestSameStartTime|TestRunCmd'`; `go vet ./internal/command` | Passed. This excludes tests that terminate real processes. `TestCapRunCmdOutput` was not selected |
| Agent real source: `go test ./internal/collectors -run 'TestPowerShellScriptBlockParsing|TestProcessTable|TestTrusted|TestImageFrom|TestFilter|TestRateLimiter'` | Build blocked with CGO disabled: `c.session_ undefined` (method lives in the CGO file) |
| Temporary agent copy with explicitly failing `windows && !cgo` `session_` stub: `go test ./internal/collectors -run 'TestPowerShellScriptBlockParsing|TestFileIdentity|TestTrustedOSProcess|TestImageFromCommandLine|TestParentResolution|TestSelfTracking|TestFilter|TestRateLimiter'` | Passed; file identity tests perform read-only signature checks plus temp-file tampering. Stub never starts ETW and is NOT in the repository |
| Same temporary copy after PowerShell changes: `go test ./internal/collectors -run 'TestPowerShellScriptBlockParsing|TestPowerShellFragmentReassembly'`; `go vet ./internal/collectors` | Passed; synthetic XML/reassembly, no policy or live logging changes |
| Same copy after process snapshot/provenance changes: `go test ./internal/collectors -run 'TestParentResolution|TestSelfTracking|TestTrustedOSProcess|TestImageFromCommandLine'`; `go vet ./internal/collectors` | Passed; no production ETW verification |
| Dashboard: `npm.cmd run build` | Final build passed (tsc + Vite). Intermediate TS2322 from `unknown && JSX` was fixed. Existing Recharts circular-chunk warnings remain |
| Dashboard: `npm.cmd exec eslint -- src/pages/automation/AutomationRulesPage.tsx src/components/alerts/AlertDetailPanel.tsx src/components/automation/ResponseActivityBell.tsx src/components/automation/AlertResponseHistory.tsx src/components/alerts/AlertEvidencePanel.tsx src/pages/automation/DetectionExceptionsPage.tsx` | Final pass, zero output. Earlier typing/non-null/hook/purity issues in these files were fixed |
| Mock browser through computer-use skill | Passed effective switch change, exact-ID/OR edit preservation and MITRE save. `CODEX_HANDOFF_UI_VERIFICATION.json` contains actual synthetic request payloads; PNG shows the rendered mock result. The fixture initially had module-loading/PATCH handling issues, fixed before the successful checks |
| `git diff --check` | Passed |
| `docker info --format '{{.ServerVersion}}'` | Unavailable: Docker Desktop Linux engine pipe absent. No containers/services started |

No race detector was executed (Windows CGO compiler unavailable). No live process-termination tests, firewall isolation, policy enable/restore, production deployment, or end-to-end event→alert→response check was performed. The temporary stub cannot prove the real CGO collector builds or works. No claim of full test-suite or end-to-end completion is made.

### Remaining work in dependency order

1. Establish a disposable Windows VM with a real CGO compiler and isolated PostgreSQL/Kafka/Redis/CM/Sigma/dashboard deployment. A focused question about this environment was sent to the user; no environment details were supplied in this turn. No production credentials are needed in this file.
2. Implement retained process-generation lineage before claiming safe orphan termination after a pre-dispatch root exit. Acceptance: never kill descendants of reused/unknown parents, but kill validated original orphans; test same-image reuse, root exit, protected/unknown children, suspension failure/cancellation and late spawns on disposable processes.
3. Complete command-path coordination if the requirement means all response entry points: unify raw manual commands, legacy triage and agent prevention with clear ownership/history; use database-backed coordination if multiple CM replicas are supported. Current engine-only serialization must not be described as comprehensive.
4. Run migration 060 and Sigma 018/019 against the shared isolated DB. Verify real schemas, exception CRUD/RBAC/admin/security/OTP/audit/expiry/hit refresh, settings fail-closed/lock, cooldown and command/execution persistence. Check notification keyset SQL, saturation (>200 executions / >100 events), outage retry and late agent-event ingestion.
5. Full CGO agent build; test actual ETW callbacks, PID identity provenance, dropped-event accounting, worker shutdown/rate exemptions and trusted-path assumptions. Then verify embedded/catalog/unsigned/tampered signatures, certificate trust/revocation policy and replacement cache behavior.
6. In disposable Windows, test 4104/4103 and Windows PowerShell/Core policy/bookmark lifecycle (restart, duplicates, missing channels, fragment boundaries, cap/expiry, uninstall restore). Replay a benign detection fixture through Kafka→Sigma alert→dashboard evidence and a fake/non-destructive response first.
7. In the VM, isolate/re-isolate/restore with recovery access; run commands over C2 while isolated; simulate DNS/C2 loss and failed firewall commands. Confirm DB state only tracks actual results and legacy triage respects the switch. Collect real command results and check manual vs automatic outcomes/history.
8. Calibrate FP/risk/UEBA on representative benign/attack replay fixtures, including sparse hosts, service restart, replayed data and exact-rule low-severity opt-in. Fix the separate pre-existing CRL vet issue through focused investigation, rather than suppressing it.
9. Clarify the older rule-sync/related-ID backlog acceptance criteria before expanding scope. This repository's older memory is evidence of pending work, not a complete requirement document.

### Standards and policy evidence

[Official Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) describes rule levels and analyst review expectations. [Microsoft PowerShell logging documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) documents Script Block Logging / event 4104. These support preserving rule levels and collecting the actual script source. The specific numeric risk bonuses and High/Critical-or-exact-ID containment policy in this code are local platform choices; this session did not establish any universal standard prescribing those numbers or automatic containment. Production safety/performance/FP improvement remains to be measured.

### Transfer artifacts

- `CODEX_HANDOFF_UNSTAGED.patch` / `CODEX_HANDOFF_STAGED.patch` and `CODEX_HANDOFF_UNTRACKED.txt` preserve the baseline recovery state; they are intentionally not overwritten with later edits.
- `CODEX_HANDOFF_FINAL_UNSTAGED.patch` and `CODEX_HANDOFF_FINAL_UNTRACKED.txt` preserve the latest working state, including the continuation changes. Transfer the listed untracked SOURCE files separately; patches never include them. Handoff artifacts are excluded from that list and should be copied separately when needed.
- `CODEX_HANDOFF_UI_FIXTURE.mjs`, `CODEX_HANDOFF_UI_VERIFICATION.json`, `CODEX_HANDOFF_UI_VERIFICATION.png` are mock-only proof/reproduction artifacts. The fixture uses absolute paths for this checkout and synthetic role/data; do not deploy it as production UI/auth.
- No secret/config file was exported. Patch credential checks were heuristic, not a guarantee; review securely before sharing outside the intended project.
Final export check: {"finalPatchBytes":259299,"requiredUntracked":33,"baselineFilesPreserved":true,"stagedFiles":""}. Baseline patches retained unchanged. The final binary diff passed the same heuristic credential scan.


## 2026-10-09 continuation — latest implementation state

This section supersedes older continuation limitations where explicitly resolved below. The user reserved actual system/endpoint testing for themselves and authorized completion of programming and fixes. Codex performed development-only verification with pure/mocked tests, temporary executables that were not run, and a new loopback-only disposable PostgreSQL cluster. No deployed database/configuration or EDR endpoint was used for responses.

### Attribution and preservation

The recovery snapshots distinguish inherited files from subsequent Codex edits. They are evidence of the inherited state, not proof that Claude authored every difference. CLAUDE_CONTEXT.md and the earlier requirement table remain the source of recovered scope; absent acceptance/conversation details remain unknown. No reset/stash/clean, commit, stage, service installation, endpoint quarantine/isolation/termination, or change to sigma_engine_go/config/config.yaml was performed. All source paths listed in the prior final untracked inventory were still present when checked this turn. Earlier handoff patches and inventories were retained.

### Completed programming changes and evidence paths

- CM `internal/response/coordination.go`, `engine.go`, `cmd/server/main.go`, `pkg/api/handlers_agents.go`: raw commands, new response playbooks and legacy post-isolation triage share one endpoint gate, held through result wait. Idle entries are removed, cancellation releases only the owned token, and shutdown admission is synchronized with WaitGroup.Wait. UUID/prefix normalization avoids separate locks for the same endpoint. Legacy queued triage rechecks the automation switch and current isolation state.
- CM `pkg/playbook/engine.go`: a Send success is delivery admission only. Steps/runs now wait for actual persisted terminal results, propagate failures/cancellation/offline/persistence failures, respect per-step expiry and preserve final state with bounded contexts. Unknown result labels cannot become success.
- CM `internal/repository/command_policy_repo.go`: respects explicit expiry; nil error strings decode correctly; late send/ACK/executing updates cannot regress a terminal result. Invalid status and result JSON encoding errors are rejected.
- CM `pkg/server/server.go:SendCommandResult`: checks mTLS-derived context identity against payload and command owner before writes or side effects. Only recognized terminal labels are accepted. DB failures return a retryable error; result bodies are no longer copied wholesale into informational logs. `pkg/server/command_result_test.go` exercises rejected identities/statuses and successful/cancelled results using repository doubles.
- Agent `internal/grpc/client.go`, `result_retry.go`: bounded delivery retry of the same immutable result (five attempts, 30s total, 8s per RPC, transient codes only). Never retries command execution. Permanent errors/cancellation terminate retries. Long outages and process exit can still lose undelivered results; this is not a durable result outbox.
- Agent `internal/actiongate`, `command/handler.go`, `responder/process_engine.go`, `agent/agent_windows.go`: local process prevention calls the same measured-image/start-time native terminator as remote commands. PID-only taskkill was removed. Mutating local/C2 actions share a context-aware gate; read-only forensic commands remain classified explicitly. Unknown response actions fail validation, and cooldown identities include measured generations with bounded memory.
- Agent `internal/processlineage`, `collectors/process_pipeline_windows.go`, `command/terminate_windows.go`: retained measured PID generations and verified parent generations allow matching observed descendants after their original root exited or its PID was reused, while replacements stay untouched. Late process-start/end workers cannot overwrite or mark a newer generation exited. Original ETW FILETIME timestamps now drive event-time checks. Retention is 10 minutes/65,536 generations, with explicit gap/eviction tracking. An exited-root tree still reports full completeness unverified; verified descendants can be targeted, but unobserved ancestry is never guessed.
- Agent `collectors/etw.go`, `process_pipeline_windows.go`: cancellation joins bounded worker pools, stops per-session goroutines, prevents restart with prior workers alive, replaces stale queues before a new session, and cancels delayed retry/snapshot work. UTF-16 C buffers are read with unsafe.Slice rather than uintptr pointer arithmetic. DNS/pipe unused variables found by genuine CGO compilation were removed. Live PowerShell/process-response tests now require explicit EDR_RUN_LIVE_TESTS=1; pure tests do not open ETW sessions or execute endpoint responses.
- CM `internal/repository/crl_cache.go`: publishes revoked maps under RWMutex instead of copying an in-use sync.Map. Concurrent additions survive refresh. Failed last-seen writes and newer in-flight observations remain buffered; short fingerprints no longer panic in log formatting.
- CM `prevention_activity_repo.go`, `pkg/api/handlers_prevention_activity.go`, `server.go`, migration061; dashboard `ResponseActivityBell.tsx`, `activityWindow.ts`: prevention notifications use ingestion time and an ascending (created_at,id) cursor, so delayed events remain discoverable. Executions/events retain independent fixed-upper-bound windows across saturated batches and outage retries; bootstrap history does not toast. Node tests drain tied/saturated pages and reject stagnant cursors. Dedup memory is bounded (10,000 keys); notification delivery is best effort under extreme churn/very long transaction delays.
- Sigma `application/rulesync/runtime.go`, `rules/parser.go`, `rules/quality.go`, `detection/{compiled_rule,detection_engine}.go`, `handlers/{rules,server}.go`, Kafka main: DB rule edits publish an atomic detector snapshot immediately and refresh every30s. Disable/delete changes affect live evaluation. DB outages keep the last snapshot. Rule content is parsed/compiled before API writes, metadata is populated consistently, mismatched IDs/multiple documents/unsupported conditions are rejected, and runtime activation failure is reported rather than falsely claiming activation. The Test API now evaluates positive/negative events in a separate detector with the same matching configuration and no persistence/response. Legacy serialized domain-YAML seed content is supported only after validation. Seeding uses ON CONFLICT DO NOTHING so restarts preserve analyst edits; disk updates to existing IDs now require explicit managed import/update.
- Sigma `database/{repository,alert_writer,alert_repo}.go`, `handlers/alerts.go`, migration020; CM migration062/response alert reader/conditions; dashboard client/detail: related_rule_ids survive create/read/dedup/API and exact-ID automation matching. Titles and ID arrays are displayed separately because merged arrays have no positional correspondence. The shared additive column is preserved by down migrations to avoid breaking the other service.
- Sigma `application/baselines`: current/previous-hour observed counts restore from PostgreSQL without re-writing persisted buckets, caches copy snapshots and stop cleanly, and buffers/cache cardinality are bounded. Flushes are serialized and retry an immutable batch token after uncertain commits instead of merging/repeating increments. PostgreSQL migration021 records batch tokens atomically with increments. Pending+in-flight counts remain memory-resident and can be lost on process crash. Token retention30days supports bounded retry; it does not deduplicate Kafka replay of individual events.
- Sigma `application/detection/exceptions.go`, `database/exception_repo.go`, migration022: exception-hit batches are transactional, ordered to avoid inconsistent lock acquisition, tokenized for safe uncertain-commit retry, flushed with bounded contexts, and joined before DB closure on shutdown. Custom repository/source implementations lacking the optional batch interfaces retain their original at-least-once retry semantics.
- Sigma `database/migrate.go`: embedded migration paths use slash-separated path.Join so genuine Windows migration execution succeeds.

### Requirement map (verification scope matters)

| Recovered requirement | Current status | Evidence / remaining verification |
|---|---|---|
| Automation enable/disable + guardrails + exact IDs/MITRE UI | Implemented and verified in development | Prior mock UI plus current API/response regression tests/build; real RBAC/security/OTP deployment remains user testing. |
| Sequential tracked responses and legacy/raw coordination | Implemented and verified in development | CM response/playbook/coordination tests and command SQL state tests; process-local server gate, not distributed scheduling. |
| Accurate result success/failure and endpoint ownership | Implemented and verified in development | New gRPC result-handler and pure delivery-retry tests; live mTLS/reconnect feedback path remains user testing. |
| Measured process/tree identity, reused PIDs | Implemented and verified for pure identity/ancestry logic | Native CGO build and synthetic generation tests; live native suspension/termination and complete post-exit ancestry remain unverified. |
| ETW bounded workers/event times/self ancestry/trusted paths | Implemented; worker/table logic verified | Pure cancellation/late event tests; real callbacks/loss/security trust chains/signature revocation policy remain user verification. |
| PowerShell4104 fragment evidence/detection categories | Implemented and verified for parsing/reassembly/matching | Pure collector and Sigma tests; subscription/GPO/channel/bookmark behavior remains user testing. |
| Detection exceptions CRUD/filtering/hit counts | Implemented and verified in development | CM isolated CRUD/API tests, Sigma matching/atomic SQL/token/retry/shutdown tests; real auth/audit/refresh across services remains user testing. |
| UEBA event-hour statistics/current-hour exclusion/restart | Implemented and verified in development | Unit/scoring and isolated PostgreSQL restart/token tests; benign/attack replay calibration and Kafka redelivery remain unverified. |
| Running engine reflects DB rule changes + real rule test API | Implemented and verified in development | Runtime/HTTP and actual PostgreSQL edit/enable/disable/delete tests; distributed periodic propagation bounded by refresh interval. |
| Aggregated exact rule IDs survive storage/API/response | Implemented and verified in development | SQL create/dedup/read and CM response-reader/condition tests; UI build. Historical rows have empty arrays until new evidence arrives. |
| Saturation/retry/delayed prevention notifications | Implemented and verified in development | Node window tests plus SQL650 execution/450 delayed event fixtures and API projection tests; actual browser streaming/server timing remains user testing. |
| Production end-to-end detection→response correctness, FP/performance | Implemented components, unverified end to end | User explicitly owns live tests; no claim of deployment readiness, numeric-score calibration or universal standard compliance. |
| Unrecorded Claude acceptance/conversation details | Unknown due to missing context | Do not infer missing requirements from changed files or old phase-completion labels. |


### Verification actually executed this continuation

Go commands below used the installed Go1.25.5 toolchain explicitly. They were run from the corresponding module directories; no root-wide test command or deployed service was executed. Final source checks supersede earlier attempts where noted.

- CM: `go test ./internal/response ./internal/repository ./pkg/api ./pkg/playbook` passed after coordination/CRL/feed changes. After the final result-authentication and normalization edits, `go test ./pkg/server ./pkg/playbook ./internal/response` passed. Targeted `go vet` and `go build -o <temp>/codex-edr-cm-build.exe ./cmd/server` passed.
- CM isolated PostgreSQL: `TestPostgresCommandStatusCannotRegressAfterResult`, `TestPostgresActivityKeysetsDrainTiedAndDelayedRows`, `TestPostgresResponseStateAndExceptionCRUD`, `TestPostgresResponseReadsAggregatedSigmaIdentities` passed. The first command test exposed NULL error_message decoding; it was fixed and the failing test rerun successfully. SQL fixtures exercise actual selected migrations/constraints/triggers with minimal ancestor fixtures, not the full application schema/auth/services. Feed fixtures contained650 tied executions and450 delayed prevention events.
- Sigma: rule/parser/detection/handler tests passed during runtime wiring. Final `go test ./internal/application/detection ./internal/application/rulesync ./internal/handlers ./internal/infrastructure/database` passed with explicit isolated DB env vars after hit-token/shutdown changes. Baseline/scoring/alert packages passed earlier after baseline modifications. `go vet ./internal/application/... ./internal/domain/... ./internal/infrastructure/database/... ./internal/handlers/... ./cmd/sigma-engine-kafka` and Kafka server build passed.
- Sigma isolated PostgreSQL: four actual SQL tests passed: alert create/read/dedup identity contract; rule CRUD/enable/disable/delete activation in the real detector; baseline token retry plus observed-count restart; exception-hit transaction rollback plus repeated-token idempotency. All embedded Sigma up migrations001,002,014-022 were executed in new per-test databases in the final run. An initial exception fixture omitted required reason; the fixture was corrected (no schema weakening) and the test rerun. Embedded Windows path.Join correction was required for the tests to execute real migrations.
- Agent: genuine Windows/CGO full build passed after removing actual DNS/pipe unused variables and correcting C comments. Pure tests passed for retained generations/gaps/invalid parents, action-gate cancellation/idempotent release, local measured-identity refusal/rule matching, late process table exit/replacement dedup, worker cancellation, PowerShell4104 parsing/fragment reassembly, descendant generation checks, image/start comparison and RUN_CMD tier parsing. Test commands used an anchored explicit list and no live response/subscription tests. A broader earlier selection was stopped before collector tests completed because its prefix also selected the live PowerShell test; explicit opt-in guards were then added. No success is claimed for that interrupted run.
- Agent: the new pure result-delivery test passed for transient recovery, permanent denial, cancellation and five-attempt exhaustion. Final agent vet/build result is recorded below after completion. Initial vet found uintptr-based C-buffer pointer arithmetic in etw.go; it was replaced with unsafe.Slice without suppressing vet.
- Dashboard: `node --test src/components/automation/activityWindow.test.mjs` passed2 tests. `npm run build` passed TypeScript and Vite production build. Focused eslint passed for the bell/window, alert detail/evidence/exception modal/history and automation/exceptions pages. Existing Vite Recharts circular-chunk warnings remain outside these changes; passing compilation does not verify chart rendering or live browser behavior.
- Initial `go test -race` attempts across CM/Sigma/agent could not link the Go Windows race runtime using the portable Zig compiler: missing WaitOnAddress/WakeByAddress symbols. This was a toolchain-link failure, not a passed race check. A Sigma compile attempt also overlapped a newly added import while the dependency graph was already being built; stable-source normal tests/vet/build subsequently passed. Race-link recovery and final results are appended below only once actually observed.

The development PostgreSQL cluster was initialized in a random temp directory, listened only on127.0.0.1:55517, and used disposable UUID-named databases that the tests removed. The existing configured DB and schema were untouched. Tool binaries/built executables stayed in temp directories and were not installed as services or deployed. Portable Zig0.15.2 and embedded PostgreSQL17.11 artifacts were checked against their published SHA256 values.

### Deployment and user-owned continuation order

1. Retain the entire working checkout and every listed untracked source. Review the focused patches against the historical baseline; origin is not inferred from modification time. There are no commits/staged changes to merge automatically.
2. Apply additive schema changes before binaries using them: CM060-062 and Sigma018-022. Sigma startup runs its embedded up migrations; use the deployment's normal CM migration procedure. Shared related_rule_ids migration is idempotent in either service, but CM062 is intentionally a no-op if Sigma has not yet created sigma_alerts. New Sigma020 ensures the column before the new engine writes it. Do not drop shared columns while either service uses them.
3. Build/deploy all three compatible service/agent versions and the dashboard in the user's isolated environment. No deployment was performed by Codex. Existing disk rule IDs are no longer overwritten on restart; make deliberate rule imports/updates through management APIs when changing an existing rule's content.
4. User verifies one synthetic detection event across real agent ingestion/Kafka/Sigma persistence/API/dashboard, exceptions with actual roles/audit, automation switch/closed-alert/cooldown controls, and correct result ownership/status persistence over real mTLS.
5. User verifies Windows ETW timestamps/session cancellation/drop behavior, trusted/signature/catalog/unsigned/tampered fixtures and PowerShell logging/channel/fragment/bookmark lifecycle. Live test entry points require explicit EDR_RUN_LIVE_TESTS=1 and should run only in their disposable VM.
6. User verifies measured native termination against reused PIDs, protected processes and descendants that outlive their root. Expect a truthful unverified completeness result after an already-exited root; observed descendants can be terminated, but invisible generations cannot be attributed safely. Retention gaps, kernel loss and insufficient privileges remain material limits.
7. User verifies isolate/re-isolate/restore/firewall rules, C2 reachability while isolated, interrupted result delivery, file quarantine/restore failures and final state/history. Recovery connectivity must be established before their isolation tests. Durable result replay across long outages/crashes is not implemented by the bounded retry helper.
8. User calibrates FP/risk/UEBA on representative benign/attack replay, sparse hosts, repeated Kafka delivery and pressure workloads. Historical aggregation IDs are not backfilled from titles; notification dedup/overlap and lineage retention are deliberately bounded. Local/file operations still require their live path-replacement and permissions scenarios. No universal numerical scoring or EDR certification claim is made.

### Standards evidence used for specific implementation choices

[Microsoft process identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers) motivates measured generation checks. [EVENT_TRACE_LOGFILEW documentation](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew) documents ProcessTrace timestamp conversion (this collector does not request RAW_TIMESTAMP). [Go sync documentation](https://pkg.go.dev/sync) specifies that an in-use Map must not be copied. [Microsoft WaitOnAddress requirements](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress) identifies the Windows synchronization import library/DLL used while diagnosing the race-link problem. These are narrow API/library facts; they do not establish end-to-end correctness or production qualification.

Documentation recovery note: an attempted update used the Windows default encoding and failed while writing the handoff. The prior complete text was reconstructed from the same chat's local historical full outputs (57 matching overlap lines), retained as CODEX_HANDOFF_RECOVERED_20261009.md, and the latest section appended explicitly as UTF-8. No historical section was intentionally discarded.

Final preservation snapshot2026-10-09: {"branch": "Main", "head": "5a089cfa1602c3792adb74fd146d9a58385026e9", "stagedFiles": "", "patchBytes": 362688, "untrackedSources": 63, "previousUntrackedMissing": []}. Earlier patches/inventories retained; new dated export does not include untracked source content. Credential checks are heuristic only.

Final native verification: after the last result-delivery and C-buffer changes, agent `go test ./internal/grpc -run ^TestResultRetryTransientRecoveryPermanentFailureAndCancellation$ -v`, targeted agent/collector/command/responder/grpc `go vet`, and genuine CGO `go build -o <temp>/codex-edr-agent-build.exe ./cmd/agent` all passed (exit0). Final CM and Sigma targeted vet/build pipelines also returned exit0.

Race verification limitation: direct race linking failed on missing Windows synchronization exports. Linking with `-extldflags=-lsynchronization` failed because the portable Zig distribution lacked that library name. Linking the supplied `api-ms-win-core-synch-l1-2-0` import library succeeded, but execution then failed in ThreadSanitizer before the test could complete: allocation1048576 bytes at0x100ef11ed0000 returned Windows error87. Race tests therefore remain UNVERIFIED on this host; none is reported as passed. No project compiler flags or production ASLR behavior were changed to work around this environment limitation. Normal concurrency regression tests passed as listed above.

The isolated PostgreSQL cluster was shut down using its checked temporary data path and pg_ctl. No application service was started or stopped. Built executables were not run. Final git diff --check passed; branch Main/HEAD5a089cfa1602c3792adb74fd146d9a58385026e9 stayed unchanged and nothing is staged.

## 2026-10-09 — Detection Exceptions redesign and navigation-load fixes

This section supersedes older UI state descriptions above. Baseline for this continuation: clean Main at 8465fc2caf39b23a09e544c7f1adc486859cb1f2 (the preceding changes were pushed). The work below is in the working tree; no commit or deployment was performed in this continuation. Existing config/env values were not changed.

User scope: redesign Detection Exceptions and its shared creation dialog to match the platform, eliminate horizontal overflow in Conditions, enable endpoint selection for direct creation, verify controls, explain/fix misleading empty-condition validation, and investigate slow navigation and buttons. Live endpoint response/system testing remains user-owned.

Implemented and verified:
- dashboard/src/components/alerts/CreateExceptionModal.tsx: the same responsive form serves New exception and the alert's False Positive… action. Uses platform input/button styles, minmax(0, ...) grids, compact condition rows, mobile stacking, accessible labels, and explicit field/operator/value guidance. Error messages focus into view. Selected empty conditions are rejected, never silently omitted. Draft state resets on reopen/alert change; maximum 10 condition rows; all four operators and five expiries remain available. Rules from aggregated alerts can be selected by ID without inventing title associations.
- dashboard/src/components/alerts/exceptionForm.ts: shared validation/payload logic and evidence prefills. The old message came from filtering checked rows by non-empty value after a width conflict hid the value input. Selecting Image alone is not a complete condition. Errors now identify the field and missing value. Legacy event_data/image_path/Image evidence is supported, without inventing missing paths.
- dashboard/src/components/alerts/ExceptionEndpointPicker.tsx: specific endpoint selection works with or without a source alert, with server-side search, 20-row pagination, retained selection, stale-response protection, and retry. Failed pagination cannot skip a page. All-endpoint scope explicitly omits agent_id.
- connection-manager/pkg/api/handlers_exceptions.go: creating an endpoint-scoped exception now rejects missing/deleted endpoints and unavailable lookups before persistence, instead of swallowing lookup errors.
- Creation locks controls and closing while saving; repeated submission is guarded. Once create succeeds, a failed alert-status/callback update retries only the follow-up, avoiding another create. useAlerts.handleStatusChange now exposes completion/failure to this caller. Alert exception creation respects admin/security roles.
- dashboard/src/pages/automation/DetectionExceptionsPage.tsx: responsive exception cards, state/hit summaries, search/state filters, visible load/action errors, guarded enable/disable/delete operations, and an in-app delete confirmation with retry feedback. Expired entries cannot be falsely reactivated using the enabled toggle.
- dashboard/src/components/Modal.tsx: unique accessible titles, keyboard focus containment, topmost Escape ownership, busy close protection, and reference-counted body scroll locking. A browser regression reproduced Escape closing the parent alert after closing the child; consuming Escape in the topmost modal fixes that case.
- dashboard/src/api/client.ts:createAlertStream: cleanup now permanently disposes a stream and detaches callbacks; closing a page can no longer trigger the old onclose reconnect path. Stale callbacks are ignored and connection state is exposed to callers.
- dashboard/src/hooks/useAlerts.ts, useDashboard.ts, alertRefresh.ts: replaced redundant one-second polling with stream-triggered fixed-window batches plus 30-second connected reconciliation; disconnected fallback is 5 seconds for lists and 10 seconds for dashboard alert statistics. Batches do not starve under continuous traffic or cancel an in-flight query repeatedly. Hidden pages mark data stale without immediate refetch; focus refresh is retained. Seen/highlight sets and pending dashboard updates are bounded. Existing IDs still trigger refresh for aggregation updates. Dashboard streaming rows are merged with authoritative recent results.

Actual final verification:
- npm run test:exceptions: PASS. Nine Node tests plus a real Chromium browser using actual React components, actual hooks, and platform CSS with isolated loopback API fixtures and an in-memory EDR socket. Covers 25 fields, four operators, five expiries, checked blank conditions, all/specific scopes, endpoint search/pagination/failure/races, condition add/remove/limit, creation failure/retry and duplicate-submit guard, alert follow-up failure without duplicate creation (direct and callback paths), refresh, filtering, toggle/delete errors and retry, read-only access, reopen/reset, nested modal Escape/body lock, and keyboard focus containment.
- Browser layout checks passed at widths 320, 390, 768, and 1280 with no horizontal form overflow or off-dialog controls; light/dark screenshots inspected. Screenshots: C:/Users/onyxv/AppData/Local/Temp/edr-exception-ui-verification/.
- Browser performance regression: zero additional alert/stat requests during 3.2 seconds of connected idle time; 30 streamed events produced 2 list refreshes and reached the UI. Ten page transitions followed by leaving retained zero EDR sockets, with no reconnect after cleanup. HTTP fallback refreshed during a simulated socket outage. These are fixture measurements, not production latency measurements.
- Final focused ESLint on all changed UI components/hooks/helpers: PASS, no diagnostics. TypeScript/Vite npm run build: PASS. Existing Recharts cross-chunk circular dependency warnings remain.
- CM: go test ./pkg/api -count=1, go vet ./pkg/api, and go build ./cmd/server to a temporary executable: PASS. New TestCreateExceptionRejectsUnverifiedEndpoint covers malformed IDs, absent service, deleted/missing endpoint, and lookup failure before database writes. Targeted condition validation tests also passed.
- Sigma: go test ./internal/application/detection -run '^TestException' -count=1: PASS (scope/host/expiry safety, hit retry and shutdown cases).
- git diff --check: PASS. The browser fixture closes its disposable browser and local Vite server in finally. Built server executable was not run.

Remaining verification/deployment:
- The screenshots supplied by the user show the prior deployed dialog. Rebuild/deploy the modified dashboard and CM to see these changes in that environment.
- No live database profiling, deployed HTTP timing, production approval-email flow, or endpoint mutation was performed. Do not claim that every cause of deployed latency is resolved. Multiple aggregate queries in Sigma GetStats may still require profiling against actual data if latency persists.
- No fresh live EDR end-to-end run is claimed; prior live-testing limitations above still apply.


## 2026-10-09 — MITRAS commercial branding

- Replaced active dashboard product branding, login/header artwork, page titles, browser icon, report preview/export titles and filenames with MITRAS. Shared component: dashboard/src/components/MitrasLogo.tsx.
- Original user-supplied transparent PNG preserved byte-for-byte at dashboard/src/assets/mitras-logo.png. SVG viewBox selects the emblem or full wordmark without editing pixels. Browser favicon embeds that artwork; exported HTML/Word/print reports embed it as a data URL for offline use.
- Updated MFA/approval email product text, template SMTP sender display name, new certificate organization/root-CA display name, Windows service display name and CLI product messages. Existing certificates are not regenerated. Service identifier EDRAgent, registry/storage paths, API/module names, integration bot handles and technical EDR terminology remain compatible. Existing installations need an updated deployment to display changes.
- Verification: dashboard npm run build passed (existing Recharts circular-chunk warnings remain); isolated Chrome login smoke check passed at 390 and 1280px in light/dark, including artwork decode, title, favicon HTTP response and no horizontal overflow. Screenshots: system TEMP/mitras-branding. Connection-manager go test ./internal/service ./pkg/security -count=1 passed; service package has no test files. No emails sent and no endpoint actions run.
- Final compilation: connection-manager ./cmd/server and Windows agent ./cmd/agent (CGO with existing Zig wrapper) both passed; binaries written only to system TEMP and never executed. git diff --check passed. Legacy unused public logo files removed. Changes are local, not committed/pushed or deployed in this branding task.


## 2026-10-10 — General detection and reliable alert delivery

User scope: behavioral detection across malicious activity, including but not limited to Atomic Red Team. No specific failed technique, deployed endpoint event or execution time was supplied. No claim is made about the cause of the user's live test. Actual endpoint/attack testing remains user-owned.

See DETECTION_RELIABILITY_REVIEW.md for the complete implementation map, deployment steps and remaining operational checks. Existing MITRAS changes and staged files were preserved; staging observed on continuation was not authored by this turn. HEAD remained 3778a57c. No commit, push, deployment, production DB access or real endpoint response was performed. sigma_engine_go/config/config.yaml is unchanged.

Changes: agent default process-name/Temp exclusions removed; PowerShell channel handoff now waits with cancellation and does not advance the subscription bookmark past an undelivered record; legacy global image whitelists no longer bypass behavioral rules; Sysmon 15 routes to create_stream_hash (9 retains the correct Sigma raw_access_thread category); Kafka source acknowledgement follows persistence and synchronous broker confirmation, with bounded worker backpressure/retry and ordered single-reader registration; offset backlog capped at 4096 and metadata-only entries; merged alerts broadcast, WebSocket filter reads synchronized, saturated clients reconnect and UI reconciles on reconnect. Full alert/command evidence removed from the touched diagnostic/error logging paths. Existing rule filters, audited exceptions, rule quality configuration and response guardrails retained.

Verification executed:
- Sigma tests: kafka, detection, database, handlers and domain packages passed. Real-DB tests requiring an explicitly disposable DB were skipped, not claimed as executed. After later edits, all kafka/handlers/database package tests and the targeted shipped-rule, legacy-allowlist, ordered delivery, cancellation, offset/parser and actual loopback WebSocket tests passed.
- Final Sigma go vet of detection/kafka/database/handlers and build of cmd/sigma-engine-kafka passed.
- Agent config/filter pure tests passed. Five explicitly selected collector tests passed on final PowerShell code: default Temp/masquerading evidence, fragment reassembly, XML parsing, blocked receiver beyond the old two-second drop deadline, cancellation/replay. No live subscription or attack command was invoked.
- CM go test ./internal/response ./pkg/server -count=1 passed. Actual automated actions remain unverified.
- Dashboard npm run test:exceptions passed nine Node tests and the Chromium fixture, including new reconnect reconciliation. Production build and focused ESLint for useAlerts/useDashboard passed. Existing Recharts circular-chunk warnings remain.
- Remaining validation: production-like broker rebalances/crash recovery, actual SQL transactions/outbox semantics, native PowerShell subscription/bookmark rollover, completeness of telemetry sources and rules, long-running performance/load/FP calibration, and real endpoint response. Delivery is at least once, not exactly once; no transactional outbox was added. Downloading all rules does not enable disabled/experimental/unsupported rules or create missing event sources.

Operational note: existing endpoint YAML exclusions survive binary upgrades and must be reviewed when deploying. The changes use bounded backpressure rather than throwing away detected alerts during an outage; lag can grow and permanently invalid messages/persistence failures require operator repair. Browser events remain best effort with HTTP reconciliation.

Final 2026-10-10 verification: Windows/CGO agent go vet ./internal/config ./internal/collectors and go build -o <TEMP>/mitras-agent-detection-final.exe ./cmd/agent both passed (exit 0). Final Sigma vet/build passed. Dashboard focused ESLint passed. Built executables were not run. Both staged and unstaged git diff --check passed. New PowerShell edits and the review/handoff additions were left unstaged; previously staged changes were preserved.

## 2026-10-10 — Atomic inventory, evidence preservation and transparent branding

Baseline was clean Main/691cfc37. Latest scope: all Atomic test coverage and transparent MITRAS logo. See docs/detection/ATOMIC_COVERAGE.md for detailed evidence, per-test fixture GUIDs, requirement status, runtime integration and ordered continuation. No claim of complete Atomic/end-to-end coverage is made.

- Found and fixed a concrete detection defect in FieldMapper.ResolveField: redundant unescaping corrupted already JSON-decoded UNC/device paths and PowerShell strings. The raw-volume Atomic fixture failed before this fix. New mapping regression tests and full detection/Kafka package tests pass after preserving original values.
- Four new rule IDs/files under sigma_rules/rules/edr_custom cover PowerShell raw-volume reads, browser enumeration/history extraction (script and process), and named-pipe integrity reduction. Eight GUID-linked synthetic cases each verify positive, nearby negative and wrong-source behavior; ordinary and aggregate detection agree. These are not endpoint/attack execution results.
- New offline cmd/atomic-coverage inventories the pinned official Windows index at revision 388942adbd9641f4dfdcf079d7efe9a75ec0ac43: 1253 unique tests; 2180 eligible compiled disk rules; 1085 exact-technique candidates, 60 parent-only candidates, 108 without tagged candidates. Candidate status is never promoted to verified detection. The user's downloaded Atomic path/version is still unknown. CSV and summary are in docs/detection/.
- Removed white logo backplates from login/nav/report preview/export/favicon; retained original PNG and used a white rendering for dark UI. Isolated Chrome login checks at 390/1280px in light/dark passed transparency, contrast-filter and no-overflow assertions; screenshots inspected.
- Executed successfully: go test of atomic-coverage/mapping/detection/kafka packages; Sigma vet and build; CM internal/response and pkg/server tests with mock endpoint dispatch; dashboard TypeScript/Vite production build. Full check detail/limitations are in the coverage document. Built binaries were not executed.
- No live response policies enabled, agent configuration changed, attacks executed, deployed DB written, commit or push. Full-test evidence, unsupported telemetry/OS coverage, deployed runtime rule states, live alert/response outcomes and load verification remain incomplete. Continue by validating the user's Atomic revision and endpoint evidence, then closing telemetry gaps before claiming additional per-test coverage. Do not enable indiscriminate containment to satisfy a test count.

## 2026-10-10 — User's T1087.001 tests and investigation response

Baseline clean Main/f4db096f. User supplied remote endpoint path C:\AtomicRedTeam\atomics, 344 technique directories, Invoke-AtomicRedTeam installed version 2.3.0 and bundled manifest 2.1.0, and execution log entries for T1087.001 tests 8/9. Supplied index.yaml SHA-256 exactly matches the official pinned revision from the earlier inventory (08F8BD071D96261E12E520A8BBA4EF85DF33E611491F2435671D4F8FE94C49A4). This confirms the index, not deployed binaries or every payload. The path is absent on the coding host. User has not checked whether related net.exe/PowerShell records appear in Events; original live miss is not yet localized.

See docs/detection/LOCAL_DISCOVERY_VALIDATION.md for requirement map, IDs, exact validation, limitations and deployment sequence. Added three source-specific Sigma rules for local account/group discovery (process, ps_script, ps_module), independent of parent process; tests reject account modification, unrelated commands and wrong module invocation. Existing third-party Get-LocalUser/T1098 classification remains a documented runtime-tuning issue; no existing/operator rule was overwritten.

Added CM migration 063: investigation playbook and exact-rule automation policy, collecting bounded Security/Windows PowerShell/Core logs (200 per channel, 15-minute lookback, 60-second timeout), 30-minute per-endpoint cooldown, preserving the global automation switch. Migration is not deployed. ON CONFLICT preserves operator state; rollback disables and retains referenced records. No automatic containment was added.

Fixed a reproduced response defect: collect_logs action catalog stripped max_events/time_range. Catalog now preserves both, validates positive event limits up to 5000 and lookbacks from 1m to 168h. Agent query now selects newest matching events first, does not fall back to unfiltered history on query failure, and structured collection inherits command cancellation instead of an unrelated background timeout.

Actual verification: full Sigma detection/Kafka/handlers tests and build passed; full CM response/server tests, response vet and server build passed; real migration test on disposable loopback PostgreSQL 17 passed (initial launcher wait-tree error corrected, cluster stopped); agent synthetic XML collector tests plus bounded collection/cancellation tests passed, final Windows/CGO agent build passed. No live collector subscription, Atomic execution or endpoint response was run. Three new rule paths were tested through the actual detection worker with fake persistence/broker barriers. Policy tests read shipped migration JSON, prove correct ID matching, no dispatch when disabled/unmatched, replay deduplication and collection bounds. They are component/integration fixtures, not a live cross-service E2E run.

Added scripts/Collect-AtomicReadiness.ps1, syntax-checked read-only diagnostics for the user's endpoint. It records module/logging metadata, bounded matching event metadata (text opt-in), library hashes/definitions and recent runner log; never runs Atomic, changes settings or uploads anything. Inventory refreshed to 2183 eligible compiled rules, zero parse/compile rejection; candidate counts unchanged and not treated as coverage evidence.

Remaining: deploy new services/agent and migration, verify runtime rule IDs/policy, start a new PowerShell session after logging policy takes effect, correlate actual endpoint records with Events/Alerts/response results, and close remaining Atomic coverage/telemetry gaps. Full-test and deployed end-to-end operation remain unverified. Changes remain local; no commit or push.

## 2026-10-10 — Evidence-based recovery of deployed ingestion and stored rules

Baseline clean Main/28d0958c. User supplied Ubuntu diagnostics and an additional
startup log. Confirmed: at 07:54:02Z Redis returned LOADING while restoring its
dataset; CM discarded its client and never retried. Four hours later StreamEvents
and Heartbeat were still rejected for stale revocation checks despite Redis being
healthy. Independently, Sigma rejected legacy seeded rule content for missing
condition selections and loaded only 630 rules in the supplied snapshot. Kafka
lag zero was historical progress, not proof of current ingress.

Full recovered evidence, paths, changes, executed checks, Ubuntu deployment
commands and ordered live acceptance criteria: docs/detection/INGESTION_RECOVERY.md.

Implemented: bounded required Redis startup with resource cleanup; per-certificate
revocation freshness (no boot grace or cross-certificate trust); bounded readiness
checks and Compose readiness probe; canonical Sigma seeding and strict legacy
content compatibility without overwriting DB rows/operator settings; runtime
active/rejected/filtered counts. Added scripts/Collect-ServerDiagnostics.sh for
read-only Ubuntu diagnostics (the earlier PowerShell script is Windows-only).

Verification: regression reproduced legacy parse failure before fix; all 2183
eligible shipped rules round-trip through canonical/legacy stored formats and
compile with unchanged detection semantics. Real disposable PostgreSQL legacy
recovery and full Sigma DB tests passed; Sigma rules/rulesync/detection/Kafka/
handlers/entrypoint tests passed. CM cache/server/API/Kafka/response tests passed,
including loopback Redis LOADING recovery, deadline failure, revocation outage
and readiness cases. Local-discovery worker tests now cover both stored formats
for all three sources with fake durable-delivery barriers. Response dispatch is
mocked; no live endpoint actions. Targeted vet/build and Bash syntax checks pass.

No deployment, commit, push, new rule-enable override, certificate replacement,
Redis purge or broker offset reset. Live endpoint ingestion, browser notification
latency and actual command results must be checked after deployment; full Atomic
coverage and live end-to-end completion are not claimed. Older audit FK failures
and canceled count queries in the log remain separate uninvestigated findings.

Final verification for this recovery: CM and Sigma Linux/amd64 CGO-disabled builds
passed; final certificate-cache regression passed after bounded eviction change.
Disposable PostgreSQL was stopped; git diff --check and final Bash syntax check
passed. Changes remain local and unstaged on Main; HEAD remains 28d0958c.

## 2026-10-10 — Single-rule alert persistence blocker after ingress recovery

Baseline clean Main/6cfe11e7. User deployed preceding recovery changes. New Ubuntu
diagnostics at 13:23–13:24 UTC show healthy dependencies, advancing heartbeat,
fresh Events and Kafka publication. Sigma detects four alerts but cannot store
them: related_rule_ids SQL NULL violates migration 020's NOT NULL. Four workers
retry these failed deliveries; Events stays 543, Published 0, Kafka lag 118466.
This is a persistence blocker, not evidence of absent rules for the user's tests.

See docs/detection/ALERT_PERSISTENCE_RECOVERY.md. Single-match aggregated detection
correctly has no secondary IDs (nil Go slice). pgx writes this as explicit NULL,
bypassing the empty-array DB default. Fixed both PostgresAlertRepository.Create
and UpsertWithDedup by normalizing nil to an empty slice, preserving nonempty IDs,
primary identity, NOT NULL constraint, operator settings and delivery ordering.
No migration or change to response/agent/rules is needed.

New actual detector → generator → AlertWriter → isolated PostgreSQL regression
failed with the same SQLSTATE before the fix, then passed insert/merge and the
post-commit notification callback. Six nil/empty/nonempty Create/Upsert cases and
merge preservation passed. Full database/Kafka/handlers/alert packages passed
with isolated DB enabled; targeted vet and Linux Sigma build passed. Previous
DB identity tests populated secondary IDs and did not cover this single-match
case. Live browser delivery, exact Atomic test matches and endpoint response
still need confirmation after deployment. No commit, push or deployment here;
the production .env modification shown in diagnostics is untouched. Do not reset
Kafka offsets; monitor backlog draining after rebuilding only sigma-engine.

## 2026-10-10 — Alert evidence presentation and missing-context handling

Baseline: clean Main/be0abf2b. User supplied alert JSON proves file data.name was
being displayed as the creating process, even when process_name=unknown and
process_path was empty. Other records contain an explicit powershell.exe actor.
No attribution across these different events is justified.

Changes:
- dashboard/src/components/alerts/alertEvidence.ts centralizes scalar, event-aware
  presentation: Image aliases and process_name are distinct from file name/path;
  generic name is a process fallback only for explicit process event types.
  Current raw context is not filled from another legacy event or scoring snapshot.
- AlertEvidencePanel and AlertDetailPanel use the same evidence in Summary and
  Events, label Image and TargetFilename, show missing identity explicitly, retain
  false/zero metadata, wrap long paths responsively, and preserve raw JSON access.
- Historical file-name-only snapshots matching the represented file target are
  suppressed in the display copy; stored evidence is untouched. Context explicitly
  identifies its scoring-time scope (possibly a different aggregate occurrence).
- risk_scorer.go snapshot builder now stores actor aliases, not file target names.
  Detection logic, scoring calculations and response guards were not changed.
- ProcessLineageTree no longer calls absent lineage normal. UEBAPanel handles
  missing score_breakdown and burst data without crashing or displaying NaN.
  The first browser regression exposed this pre-existing missing-context crash;
  it passed after the targeted correction.

Verification executed: 5 new Node evidence regressions and 7 existing exception
form tests passed. Real React alert-panel Chromium fixture passed Summary/Events/
Context and raw JSON toggle, missing/known actor cases, partial snapshot, 390px
and 1280px in light/dark, no horizontal page overflow or JS errors. Screenshots
in system TEMP/mitras-alert-details. Full Go scoring package tests and targeted
vet passed. Dashboard production build passed (existing Recharts circular-chunk
warnings); TypeScript and focused ESLint passed after context handling fixes.
Reusable test: npm run test:alert-details. No live endpoint actions, deployment,
commit or push. Deploy dashboard and sigma-engine to apply UI and new snapshot
fixes; no agent rebuild or DB migration required. Missing historical actor data
cannot be reconstructed by this presentation fix. Live deployment remains unverified.
