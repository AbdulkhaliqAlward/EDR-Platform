# Ingestion and stored-rule recovery — 2026-10-10

## Recovered state before changes

Baseline: clean `Main`, HEAD `28d0958c` (`After fix Atomic read team`).
Evidence: user-supplied Ubuntu Docker diagnostics, captured October 10, 2026.

- Connection Manager repeatedly rejects the Windows agent's StreamEvents and
  Heartbeat with Unavailable: revocation cache age approximately four hours,
  maximum five minutes. Redis itself answers PONG. Startup CM logs are missing;
  the initial Redis connection error (credentials, network, or startup timing)
  cannot yet be established from this extract.
- `connection-manager/cmd/server/main.go` discards the Redis client permanently
  on its initial connection failure. There is no recovery path for this nil
  client. A green HTTP health probe does not establish working ingestion.
- `pkg/server/interceptors.go` starts a global revocation-cache timestamp at
  boot despite no successful check, and any successful certificate lookup
  refreshes that global timestamp. This does not prove another certificate is
  unrevoked. Security validation must remain fail-closed.
- Sigma logs reject stored rules with unknown condition selections and load
  only 630 rules in this extract. `domainRuleToDBRule` marshals the internal AST,
  not Sigma detection YAML. `rulesync.Parse` attempts legacy decoding only when
  YAML parsing fails, not when subsequent condition validation fails.
- Kafka's active Sigma consumer is caught up (partition 3 offset 1271362, lag
  zero). This proves no backlog at the snapshot, not current event delivery.
- Previous disk-rule/component tests do not verify stored-rule round trips or
  this deployed pipeline. No current endpoint E2E success is established.

## Ordered continuation

1. Reproduce stored-rule parsing failure; correct backward-compatible loading
   and future seeding. Preserve analyst edits, enabled states and IDs.
2. Correct Redis startup lifecycle and certificate-cache freshness; test
   unavailable, revoked, unknown, stale and recovery paths without endpoints.
3. Exercise stored rules through detection and existing delivery/response
   integration fixtures; compile affected services.
4. Provide Ubuntu deployment and read-only verification commands. Verify live
   ingestion, alert and response results after the operator deploys. Never
   reset broker offsets, purge Redis, overwrite rules, or bypass mTLS.

## Confirmed cause from the additional startup log

At **2026-10-10 07:54:02Z**, CM logged `LOADING Redis is loading the dataset in
memory`, then continued with a nil Redis client. The preceding run on October 9
had connected successfully. This confirms a startup readiness race and the
permanent degraded-client bug, rather than evidence of a bad agent certificate.
The Redis daemon subsequently becoming healthy could not repair that nil client.

## Implemented changes

- `cache.WaitForRedis` retries initial connection within 30 seconds in CM main;
  failed clients are closed. On deadline CM exits instead of silently disabling
  security dependencies; Compose's existing restart policy retries startup.
  Successful clients retain go-redis's normal reconnect behavior.
- Revocation grace is now tied to the individual fingerprint's successful
  lookup, expires after five minutes, and has a bounded 4096-entry positive
  cache. Boot or a different certificate's check cannot grant access. Known
  revocations still reject during outages. No mTLS or fail-closed bypass.
- `rules.MarshalSigmaRule` emits actual Sigma YAML (fields, modifiers, keywords,
  list-of-map alternatives, condition and metadata). Seeding no longer writes
  internal ASTs or invalid title-only fallback content. Counts report actual
  inserted rows; `ON CONFLICT DO NOTHING` remains.
- `rulesync.Parse` recognizes strict legacy AST content before normal parsing,
  including wildcard conditions that previously could compile against a bogus
  `selections` field. It re-enters the regular parser/compiler. Existing DB rows
  are read without migration/rewriting and retain analyst title, severity,
  content, version and disabled state. Runtime logs summarize active, rejected
  and filtered rules separately.
- `/readyz` checks Redis/PostgreSQL and enabled Kafka dependencies, returns 503
  on failure, and omits raw connection errors. Checks have a three-second
  deadline, including Kafka controller I/O. `/healthz` remains liveness only.
  Compose now uses `/readyz` with a 40-second startup grace. Readiness is not
  proof that the entire endpoint/detection/response path works.

## Verification actually executed

- Reproduced the original legacy seed error before fixing it: unknown selection
  `selection`. Regression now passes positive/negative events, explicit and
  wildcard conditions and disable/refresh behavior.
- All **2183 eligible shipped rules** survive the actual seeding conversion,
  standard Sigma parsing and legacy stored-content loading/compilation. Their
  complete detection structures agree after normalizing unordered field maps.
  This is rule-format verification, not 2183 attack executions.
- Actual PostgreSQL 17 on a disposable loopback cluster: legacy rule loads and
  detects, stored analyst metadata/content/version remain unchanged, disabling
  it removes detection. Full Sigma database package tests also passed with the
  explicitly isolated DB enabled.
- Sigma packages `rules`, `rulesync`, `detection`, `kafka`, `database`, `handlers`
  and `cmd/sigma-engine-kafka` passed. Local-discovery delivery covers all three
  sources through **both stored formats**, actual detection workers, and fake
  DB/broker delivery barriers; acknowledgement waits for both confirmations.
- CM packages `internal/cache`, `pkg/server`, `pkg/api`, `pkg/kafka` and
  `internal/response` passed. The Redis fixture uses loopback RESP with LOADING
  followed by recovery and a persistent-failure deadline. Certificate tests use
  synthetic verified TLS contexts; no real certificate is changed. Readiness
  failure/recovery and no error-detail disclosure are tested. Response fixtures
  test the shipped local-discovery investigation policy with a fake dispatcher,
  global disable/unmatched guards, deduplication and collection bounds.
- Targeted `go vet` and service builds passed. Bash diagnostic script syntax
  check passed. No endpoint binary, Atomic payload or response was executed.

Final verification: both service builds for **Linux/amd64, CGO disabled** passed
(the deployed container target); native Windows builds also passed earlier.
The final bounded certificate-cache tests passed after the eviction adjustment.
`git diff --check` passed. The disposable PostgreSQL cluster was stopped after
verification; its randomly created test databases were removed by test cleanup.
Built binaries remain in system TEMP and were not executed.

## Ubuntu deployment and end-to-end acceptance

After transferring these changes to `/home/ubuntu/EDR-Platform`, preserve local
server edits and rebuild only the changed application services:

```bash
cd /home/ubuntu/EDR-Platform
git status --short
sudo docker compose up -d --build --no-deps connection-manager sigma-engine
sudo docker compose ps -a
sudo docker compose logs --no-color --since 10m connection-manager sigma-engine \
  | grep -E 'Connected to Redis|Required Redis|Rule runtime snapshot|Stored rule|Stats |Response'
sudo bash scripts/Collect-ServerDiagnostics.sh
```

The script gathers bounded logs, topic/consumer metadata, readiness, recent
agent/event/alert/execution metadata and the relevant policy switches using
read-only SQL with a five-second statement timeout. It never sources or dumps
`.env`, restarts services, changes offsets, writes DB rows or runs endpoint
commands. The full script has not been executed on the deployed Ubuntu server.

Check the following in order, using **new, timestamped activity** on the user's
Windows test endpoint and correlate the same agent/event/alert IDs:

1. CM connects to Redis, readiness reports dependencies OK, heartbeat last_seen
   advances, and new StreamEvents no longer fail revocation availability.
2. Source events exist on Windows and appear in Events/Kafka. Existing historic
   offsets alone are insufficient. If missing, use `Collect-AtomicReadiness.ps1`
   on Windows and inspect the agent's current logs/configuration.
3. Sigma's `Events` counter advances; expected rule IDs are enabled and runtime
   rejection count is understood (not silently bypassed). DB Alerts and browser
   notifications identify the same newly generated alert. Counts need not equal
   2183 when the operator has disabled/edited rules or configured other filters.
4. For the three discovery rules, the bounded investigation policy can run only
   when global/policy/playbook switches allow it, the endpoint is online and its
   30-minute cooldown permits it. Discovery does not imply unconditional killing
   or isolation. Check the response execution and returned command result; do
   not infer completion from an alert or queued command alone.

Deployment, real Windows telemetry, live Kafka delivery, notification latency
and actual endpoint response remain **unverified**. The supplied log also has
older audit-log foreign-key errors and canceled event-count queries; these are
separate findings, not asserted as causes of this ingress failure. No claim of
complete Atomic coverage or live end-to-end completion is made.
