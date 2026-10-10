# Single-rule alert persistence failure — 2026-10-10

## Recovered evidence

Baseline: clean Main at `6cfe11e7` (same revision reported by the user's server).
Server `.env` is modified; no server file/configuration is changed by this work.
The Ubuntu diagnostic snapshot is at 13:23–13:24 UTC (16:23–16:24 Riyadh).

- CM readiness: Redis, PostgreSQL and Kafka OK. Agent online, heartbeat advancing;
  CM publishes batches and Events contains fresh process/PowerShell/file records.
  This confirms improvement after the Redis startup fix.
- Sigma: Events 543, Alerts 4, Published 0, Errors increasing from 112 to 172.
  Repeated persistence error: `null value in column "related_rule_ids" of relation
  "sigma_alerts" violates not-null constraint (SQLSTATE 23502)`.
- Kafka partition 3: current offset 1271528, end 1389994, lag **118466**. Workers
  cannot acknowledge the matching source events while their alerts cannot be
  stored; newer tests may be behind this backlog. Do not reset offsets.
- Latest stored alerts in this snapshot are from October 8, not the new tests.
  The three local-discovery rules and their investigation policy are enabled;
  master automation env and stored operator switch are enabled too. These
  switches do not compensate for failed alert persistence.

## Root cause and focused correction

`domain.EventMatchResult.RelatedRuleIDs()` intentionally returns nil for a single
match: the primary ID is already stored in `rule_id`. The aggregated generator
and AlertWriter pass this nil slice to PostgresAlertRepository. pgx encodes it as
explicit SQL NULL, bypassing migration 020's empty-array DEFAULT and violating
its NOT NULL constraint. Both Create and the new-row branch of UpsertWithDedup
are affected. Prior real-DB identity tests supplied nonempty related IDs and
therefore missed this ordinary single-match case.

Before the fix, a new test using the shipped local-discovery process rule,
actual detector/generator/writer and disposable PostgreSQL reproduced precisely
SQLSTATE 23502. The fix normalizes nil secondary-ID slices to an empty slice at
both repository entry points. Nonempty IDs, primary identity, matching logic,
NOT NULL constraint, retry/acknowledgement order and response policies remain.
No schema migration, rule enable override or destructive repair is needed.

## Validation and deployment

Executed verification:

- Before correction, `TestSingleRuleDetectionPersistsAndNotifiesAfterCommit`
  reproduced the deployed SQLSTATE 23502 using the actual discovery rule,
  detector, aggregated generator and writer against isolated PostgreSQL 17.
- After correction, that test passes both a fresh insert and a deduplication
  merge. The persisted-alert callback reads the committed row through a separate
  DB query and verifies the canonical ID and absence of invented secondary IDs.
  This tests the notification callback, not a deployed browser or live response.
- `TestPostgresAlertOptionalRelatedIDs` passes six create/upsert cases: nil,
  empty and nonempty secondary IDs; incoming nil IDs preserve prior IDs on merge.
- Full database, Kafka, handlers and alert-generator package tests passed with
  the real-DB test switch enabled against a disposable loopback cluster.
- `go vet ./internal/infrastructure/database`, the Sigma Linux/amd64 CGO-disabled
  build, and `git diff --check` passed. The disposable cluster was stopped after
  verification. No compiled executable was run.

Tests use synthetic telemetry; no Atomic payload or endpoint response is
executed. Deployed verification still requires the updated Sigma service and
observation of persistence, notification and response outcomes. Changes remain
local; no commit, push or production deployment was performed.

After transferring this change to the Ubuntu checkout:

```bash
cd /home/ubuntu/EDR-Platform
sudo docker compose up -d --build --no-deps sigma-engine
sudo docker compose logs --no-color --since 5m --tail 150 sigma-engine
sudo bash scripts/Collect-ServerDiagnostics.sh
```

Confirm that the related_rule_ids errors stop, Events/Published counters advance,
new alert rows appear, and Kafka lag decreases across successive observations.
New tests may take time to reach the consumer while the backlog drains; no ETA
is established. Confirm the same alert ID in the UI and response execution;
policy/cooldown/evidence conditions continue to govern actual responses. Existing
enabled policies also apply to detections produced while processing the backlog.
The supplied snapshot does not establish which particular Atomic tests matched.
