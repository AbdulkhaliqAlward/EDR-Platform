# Atomic coverage recovery and extension — 2026-10-10

Baseline: clean `Main` at `691cfc37` before this work. Existing custom Atomic rules and previous delivery/response changes were already present; they were not authored in this continuation. No deployment, endpoint mutation, attack execution, commit or push was performed.

## What is complete

- Fixed `FieldMapper.ResolveField` in `sigma_engine_go/internal/application/mapping/field_mapper.go`: it used to replace every pair of backslashes in already-decoded event values with one. This corrupted raw device paths, UNC paths and script source. The new raw-volume fixture failed before the fix and passed after it. Evidence now remains unchanged across direct, ECS and agent field resolution.
- Added four behavior rules under `sigma_engine_go/sigma_rules/rules/edr_custom/`: `mitras_ps_raw_volume_read.yml`, `mitras_ps_browser_discovery.yml`, `mitras_proc_browser_discovery.yml`, and `mitras_ps_pipe_integrity_reduction.yml`. They use behavior and telemetry, not Atomic filenames or the test runner name. Status `test` means rule lifecycle, not live endpoint verification. Discovery and raw disk diagnostics are medium severity; named-pipe integrity reduction is high. Legitimate administration can still match and needs contextual review.
- Added `TestAtomicBehaviorFixtures`: eight GUID-linked inert fixtures, each with a positive event, nearby negative event and wrong-source negative event. Both ordinary and aggregate detection are checked. These fixtures prove matching on the supplied evidence, not that an actual endpoint produced that evidence or that the attack succeeded.
- Added the offline `cmd/atomic-coverage` inventory tool. It uses the actual rule loader/quality settings and compiler, deduplicates repeated tactic rows by GUID, distinguishes exact technique tags from parent tags, and refuses to overwrite an existing output file. It never runs Atomic commands, changes the DB, sends alerts or dispatches responses.
- Removed white backgrounds around the supplied transparent logo in login, navigation, report preview, report export and favicon. Dark UI uses a white presentation of the same transparent artwork. Original PNG bytes are unchanged.

## Pinned inventory and limits

Official source revision: `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` of [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/tree/388942adbd9641f4dfdcf079d7efe9a75ec0ac43).

Input: `atomics/Indexes/Indexes-CSV/windows-index.csv`; SHA-256 `c19d1c2c333d3c32dcfdc37357580bc1d9f36f0ec56d189c52f91502a808058b`. Follow-up: the user identified `C:\AtomicRedTeam\atomics` on their separate Windows endpoint. Their `Indexes/index.yaml` hash `08F8BD071D96261E12E520A8BBA4EF85DF33E611491F2435671D4F8FE94C49A4` exactly matches the same file downloaded from the pinned revision. This confirms the index, not every payload/definition byte or the actively loaded runner module. See `LOCAL_DISCOVERY_VALIDATION.md` for the supplied versions and targeted follow-up.

Generated artifacts:

- `atomic-windows-candidates.csv`: all **1,253 unique Windows test GUIDs** from the pinned index.
- `atomic-windows-summary.json`: **2,183 eligible, compilable disk rules** after the local discovery follow-up, zero loader errors and zero compile rejections; **1,085** tests with an exact-technique candidate, **60** with parent-technique candidates only, **108** without a tagged candidate.

These are candidate counts, **not detection coverage percentages**. A tag does not establish per-test coverage; missing a tag does not establish a detection failure. For example, an injection test may be detected by a rule tagged with a different technique. Even when a rule compiles, its required service/fields may not exist on the endpoint. Existing DB overrides, enabled states, exceptions and deployed versions are outside this disk inventory. CSV response status is deliberately unverified.

Linux/macOS/cloud tests are outside the Windows agent's scope. Some Atomic tests execute ordinary inventory commands or validate prerequisites and have no uniquely malicious signal. No universal maliciousness claim or automatic destructive response is attached to those commands.

## Fixture evidence

All references point to `sigma_engine_go/internal/application/detection/atomic_behavior_test.go:TestAtomicBehaviorFixtures`.

| Technique | Atomic GUID | Rule file | Verification |
|---|---|---|---|
| T1006 | 88f6327e-51ec-4bbf-b2e8-3fea534eab8b | mitras_ps_raw_volume_read.yml | Synthetic matching/routing passed |
| T1217 | faab755e-4299-48ec-8202-fc7885eb6545 | mitras_ps_browser_discovery.yml | Synthetic matching/routing passed |
| T1217 | 74094120-e1f5-47c9-b162-a418a0f624d5 | mitras_ps_browser_discovery.yml | Synthetic matching/routing passed |
| T1217 | cfe6315c-4945-40f7-b5a4-48f7af2262af | mitras_ps_browser_discovery.yml | Synthetic matching/routing passed |
| T1217 | 76f71e2f-480e-4bed-b61e-398fe17499d5 | mitras_proc_browser_discovery.yml | Synthetic matching/routing passed |
| T1217 | 4312cdbc-79fc-4a9c-becc-53d49c734bc5 | mitras_proc_browser_discovery.yml | Synthetic matching/routing passed |
| T1217 | 727dbcdb-e495-4ab1-a6c4-80c7f77aef85 | mitras_proc_browser_discovery.yml | Synthetic matching/routing passed |
| T1559 | 7a8f8ae9-6b1d-4f7b-88e7-9ea01234eee5 | mitras_ps_pipe_integrity_reduction.yml | Synthetic matching/routing passed |

## Response and deployment integration

Rules feed the existing ordinary/aggregate detector and durable alert delivery. They do not bypass response guardrails or install automatic containment policies. The local discovery follow-up adds CM migration 063 with a bounded evidence-collection policy for three exact local-discovery IDs; it runs after deployment only when server automation permits it. `connection-manager/internal/response` supports exact `rule_ids`, per-endpoint cooldowns, the server automation switch, process identity validation and endpoint ownership. The mocked response tests exercise these controls; actual endpoint execution remains user-owned.

The new rules have new IDs and are eligible under the current medium/test rule-loading configuration. Rebuild/deploy Sigma and dashboard to use this work; validate new IDs in the runtime rule list and review DB enabled states/exceptions. Existing IDs are not overwritten by disk seeding. This continuation does not change `config.yaml`, agent policy, automation settings or live databases.

For the three PowerShell rules, require script block logging and delivered 4104 evidence. Process rules require process creation with full command line. The earlier collector and durable-delivery checks are documented in `DETECTION_RELIABILITY_REVIEW.md`; their live limitations still apply.

## Continuation order and requirement status

1. **Index verified, deployed state still unknown:** the user's supplied index hash matches the pinned source. Inspect runtime rule states and deployed telemetry using `scripts/Collect-AtomicReadiness.ps1` on the endpoint. Tool invocation from `sigma_engine_go` to refresh another inventory: `go run ./cmd/atomic-coverage -index <windows-index.csv> -revision <actual-commit> -out <new-report.csv>`.
2. **Partial:** validate every candidate against per-test execution evidence. Start with the 108 untagged and 60 parent-only rows, checking behavior rather than adding technique tags just to improve counts. The eight fixtures above are the currently verified subset of this extension.
3. **Not complete:** close required telemetry gaps before adding rules that depend on missing sources (provider-specific Windows logs, native injection/memory evidence, application logs or other operating systems). Category inference alone is not a collector.
4. **Implemented but live-unverified:** exercise ingestion, persistence, notification/reconnect and response coordination with user-owned isolated endpoint runs. Record event/alert IDs, timestamps, the actual matched rule and response outcome for each test; distinguish blocked prerequisites, failed execution and no evidence from a detection miss.
5. **Partially configured:** migration 063 now supplies evidence collection for the three local-discovery rule IDs. Other per-rule response policies still need false-positive review. Use collection/analyst review for ambiguous discovery; require an explicit verified target and policy for termination/isolation. A detection is not proof a response succeeded.
6. **Complete:** transparent branding and the evidence-preservation fix; **partial:** full Atomic detection coverage; **unverified:** all-test end-to-end detection/response and production performance under load. No all-test or end-to-end completion claim is made.

## Checks actually executed

- `go test ./cmd/atomic-coverage ./internal/application/mapping ./internal/application/detection ./internal/infrastructure/kafka -count=1`: passed all four packages. Includes the eight new positive/negative/wrong-source fixture cases, JSON-decoded evidence preservation, CSV deduplication/conflict rejection and parent-technique classification. The first raw-volume case failed before the field-mapping fix, then passed with the full package run.
- Sigma `go vet ./cmd/atomic-coverage ./internal/application/mapping ./internal/application/detection` and `go build ./cmd/sigma-engine-kafka` to a temporary executable: passed; binary not executed.
- CM `go test ./internal/response ./pkg/server -count=1`: passed. Mock dispatch verifies policy matching, disable switch, guardrails, target ownership and run coordination; no real endpoint response.
- Dashboard `npm run build`: passed, with the existing Recharts circular chunk warnings. The first build result was lost when the command session disappeared; it was rerun with captured logs to obtain a confirmed exit code.
- Isolated Chrome/Vite login fixture: 390px and 1280px, light and dark, all passed decoded image alpha=0 at the corner, transparent wrapper, expected dark filter and no horizontal page overflow. Light and dark screenshots inspected; artifacts are in system TEMP `mitras-transparent-logo`. A virtual-entry preload warning occurred in the fixture; the actual page loaded and assertions passed. Report/nav/favicon changes were source/build checked, not separately browser-tested.
- No live Atomic run, production load benchmark or end-to-end endpoint check was executed. There is no new claim that all current malicious events or all Atomic tests are detectable.
