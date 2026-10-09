# Detection and alert-delivery review — 2026-10-10

## Scope and evidence

The user requested general behavioral detection, not rules that recognize Atomic Red Team by name. No Atomic technique/test number, endpoint evidence, deployed version or execution timestamp was supplied. The cause of the reported live test therefore remains unconfirmed. Existing MITRAS branding and staged work were preserved. No deployed service, endpoint response, attacker command, production database or Sigma configuration file was changed by this review.

## Implemented corrections

| Area | Correction and evidence | Verification scope |
| --- | --- | --- |
| Agent filtering | `win_edrAgent/internal/config/config.go` and `config/default.yaml`: default process-name exclusions and Windows/user Temp path exclusions removed. Names and temporary locations cannot establish that activity is benign. Explicit deployment-specific exclusions still apply. | Synthetic process/file evidence for formerly excluded names in both Temp locations passes the real filter. |
| PowerShell pressure | `collectors/powershell_windows.go:handleContext`: wait for channel capacity with cancellation instead of dropping after two seconds. On cancellation, the subscription loop does not advance its bookmark past the undelivered record and releases remaining native event handles. Cancelled handoff can be replayed without stale dedup suppression. | Synthetic XML and a blocked channel; no PowerShell command or Event Log subscription is executed. Native bookmark behavior remains a deployment test. |
| Behavioral suppression | `sigma_engine_go/internal/application/detection/detection_engine.go`: legacy global image allowlists no longer bypass all rules. Rule-authored filters and audited detection exceptions remain active. Startup reports this compatibility change. | Both individual and aggregated detection match synthetic malicious behavior even for an allowlisted system/developer executable. |
| Event routing | `domain/event_category.go`: Sysmon 15 now reaches `create_stream_hash`. Sysmon 9 deliberately retains Sigma's `raw_access_thread` spelling. | Actual shipped registry-to-ADS and raw-disk Sigma rules match synthetic evidence; process-creation negatives do not match them. This does not establish that the deployed agent collects every Sysmon event. |
| Durable alert delivery | `infrastructure/kafka/event_loop.go`, `delivery.go`: bounded parallel workers retain a matched alert through persistence and synchronous broker acknowledgement before acknowledging its source event. Retry backoff is capped, per-attempt contexts are bounded, enrichment has a two-second budget, and cancellation retains the source offset for replay. Successful persistence is not repeated during publication retries in the same running process. Suppression records only successfully delivered activity. | Real detector/worker with controlled persistence and broker doubles proves acknowledgement ordering and canonical identity. Retry, cancellation and malformed-message tests pass. |
| Ordered consumption | `infrastructure/kafka/consumer.go`, `offset_tracker.go`: one fetch/registration owner avoids registering a later offset before an earlier one and prevents first-reader channel-closure races. Detection remains parallel. At most 4096 registered offsets are retained; tracker entries retain commit metadata rather than message payloads. JSON null/non-object input cannot panic metadata insertion. | Offset-ordering, payload-retention and parser regression tests. Real broker rebalance/outage behavior remains unverified. |
| Live updates | `database/alert_writer.go`, `handlers/websocket.go`: successful merges also broadcast the canonical alert; serialize once per update; protect subscription-filter reads; disconnect saturated clients so they can reconcile instead of silently skipping frames. Error logs no longer duplicate full alert evidence. | Persistence callback tests and actual loopback WebSocket delivery/filter/overflow tests. |
| Reconnection | `dashboard/src/hooks/useAlerts.ts`, `useDashboard.ts`: schedule a bounded refresh on reconnection. | Isolated Chromium fixture verifies recovery without waiting for the 30-second poll, disconnected fallback, batched bursts and socket cleanup. |
| Response safety | Existing CM policy, approval, endpoint identity and execution coordination retained. | `go test ./internal/response ./pkg/server -count=1` passed with test doubles; no real endpoint action executed. |

## Verification record

- Sigma package tests passed: `./internal/infrastructure/kafka ./internal/application/detection ./internal/infrastructure/database ./internal/handlers ./internal/domain`. Database tests requiring an explicitly disposable PostgreSQL database were skipped; no fresh SQL integration execution is claimed here.
- After subsequent edits, targeted delivery, source-acknowledgement, offset, malformed-input, shipped-rule, legacy-allowlist and real loopback WebSocket tests passed again.
- Agent configuration and targeted filter tests passed. Five explicitly selected collector tests passed, including PowerShell blocked-channel retention and cancellation/replay. Final native build results are recorded in the continuation handoff.
- `npm run test:exceptions` passed nine Node tests plus the Chromium fixture, including the new reconnection assertion. Existing performance checks observed zero extra alert/stat requests during 3.2 seconds of connected idle, two list refreshes for 30 streamed events, and no retained sockets after ten navigations.
- Dashboard production build passed. Existing Recharts circular-chunk warnings remain. This is not a production throughput benchmark.
- Final Sigma vet/build and Windows/CGO agent vet/build passed. Staged and unstaged diff checks passed. Commands and limits are recorded in `CODEX_HANDOFF.md`.

## Deployment and remaining validation

1. Review the working tree/index and deploy compatible rebuilt agent, Sigma service and dashboard through the normal deployment process. This task did not commit, push or deploy.
2. Existing agent YAML files do not automatically inherit new defaults. Review/remove old process-name and Temp exclusions deliberately on the test deployment. Other explicitly configured exclusions, provider settings, rate limits and rule-specific exceptions can still suppress evidence.
3. No changes were made to `sigma_engine_go/config/config.yaml`. Its existing minimum rule level, allowed statuses and experimental-rule policy still limit activated rules. Downloading the complete library does not activate every rule or create the required telemetry sources.
4. On the user's test endpoint, correlate a source event ID and timestamp through collection, agent buffering, Kafka consumption, matched rule, persisted canonical alert, browser display and response outcome. Check PowerShell logging/channel permissions and collector drop counters. Test appropriate positive and benign-negative cases per technique and source.
5. Validate broker/DB outages, rebalance, process crash/restart, native bookmark replay, event-log rollover and sustained peak load. Delivery is at least once; this change does not implement a transactional outbox or guarantee exactly-once alert counts/automation across every crash boundary. Replays beyond the database aggregation window can form another incident. Malformed inputs are rejected/logged; an unrecoverable persistence error deliberately causes visible backpressure until repaired.
6. Browser streaming remains best effort with bounded queues and HTTP reconciliation. It does not guarantee delivery of every historical toast. Alert storage, retained Kafka data and the alert list are the recovery paths.
7. The pipeline cannot detect behavior that lacks telemetry or an applicable enabled rule/signature. This review does not add a universal Windows Event Log subscription or prove complete coverage of all downloaded rules. Broader collection increases volume; actual endpoint CPU/RAM, sustained detection throughput, latency percentiles and loss counters require the user's representative workload.
8. Validate automated response only on disposable endpoints: switch off/on, approval-required actions, duplicate alerts, unavailable/protected processes, PID reuse and isolation connectivity. Do not equate alert severity alone with authority to terminate or isolate.

## Primary references

- [Sigma taxonomy](https://sigmahq.io/sigma-specification/specification/sigma-appendix-taxonomy.html): rule logsource categories, including the `raw_access_thread` naming.
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): provider events and Event 15 FileCreateStreamHash.
- [Atomic Red Team getting started](https://github.com/redcanaryco/atomic-red-team/wiki/Getting-started): evaluate actual collected evidence and detection coverage for executed tests.
