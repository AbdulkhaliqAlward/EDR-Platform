# Pagination — status and verification (2026-10-11)

Not committed or pushed. Baseline `1efe3707`. The scope and design are in [INVENTORY_AND_DESIGN.md](INVENTORY_AND_DESIGN.md).
The work had two passes. Codex did the first; Claude then reviewed it, fixed regressions and completed it. This file describes the final state.

## Endpoints and chosen pagination

| Endpoint | Type | Sort keys | Indexes |
|---|---|---|---|
| Sigma `GET /sigma/alerts` | keyset, 25/100, prev+next cursors | `created_at` (`COALESCE(created_at,timestamp)`), `risk_score` | Sigma 024, 025, **026** |
| CM `POST /events/search`, `GET /agents/:id/events` | keyset on ingestion time | `created_at,id` | CM 064, 065 |
| CM `GET /commands`, `/agents/:id/commands` | keyset | `issued_at,id` | CM 066, 067 |
| CM `GET /security/events` (+ new detail route) | keyset | `created_at,id` | CM 068, 069 |
| CM `GET /audit/logs` | keyset | `created_at,id` | existing `created_at` index |
| CM `GET /agents` | offset (small table), 25/100, exact count | whitelisted + `id` tie | existing |
| Sigma `GET /sigma/rules` | offset (small table) | whitelisted + `id` tie | existing |
| CM `GET /users` | offset, capped to 100, `created_at,id` tie | — | existing |
| CM roles, permissions, enrollment tokens, context policies, detection exceptions, response scripts, automation rules, SIEM connectors, per-endpoint quarantine | full-list shape kept; response capped at 1000 (`X-Result-Truncated`) | — | — |
| Sigma `GET /sigma/incidents` (in-memory) | stable newest-first order and a 1000 cap | `created_at,id` | — |

Already bounded and left unchanged (documented compatibility):
- playbook executions (≤200, stable `id` tie)
- vulnerability findings (≤500, offset)
- signature list (≤1000)
- sync history, forensic, incident and IOC "latest N" lists
- grouped analytics (hard caps and query windows)

The NDJSON signature feed (`/signatures/feed.ndjson`, ≤50000) is a protocol for agents and was left untouched, so agent signature sync is not at risk.

## Fixes made in the review pass

1. **Alerts:**
   - Risk-score sort restored as a server keyset sort (it had been disabled). The shared package gained `KeysetInt`/`IntKey`.
   - Migration 026 `(risk_score DESC, id DESC)` was added only after EXPLAIN showed the planner actually uses it.
2. **Alert date range** now filters the creation key, the same key the list is sorted and fenced by. Before, it filtered the event `timestamp`, a second time column that drove the planner into Sort plans (78 ms → 1.5 ms).
3. **The alert list projection** had blanked `context_data`, `score_breakdown` and `context_snapshot`. It now returns only the small values the table renders:
   - the source hostname
   - the UEBA signal
   - a "context available" marker
4. **The duplicated `alerts` payload alias was removed.** Every list item had been serialized twice. The only consumer, the dashboard client, maps `data`.
5. **Alerts page:**
   - A status change re-reads the current page with the same cursor. Before, the row stayed stale and showed "refresh the list".
   - A bulk action no longer jumps to page 1.
   - The live stream is opened once instead of on every page change.
   - "New items" counts only alerts matching the active severity/status filters, and resets when the filters change.
6. **Endpoint detail, auto-termination tab:** still used `offset`, which the server rejects, so page 2+ failed. It is now a cursor-paged URL state, and an expanded row loads the full event by ID; the list projection lacks pid, ppid, command line, kill output…
7. **Command history:**
   - Lost its 8 s auto-refresh. It now refreshes the first page only, and not in hidden tabs.
   - After executing a command, the history was not refreshed because the query key had changed (`['agent-commands','page',id]`). The invalidations were fixed.
   - The Action Center (30 s) and Endpoints (10 s) first pages refresh again, as they did before.
8. **Legacy `list` wrappers** for agents, alerts and event search were silently cut to 100 rows; callers request 200/500/1000. `readUpTo` now reads consecutive ≤100-row pages up to the requested count. The report/correlation loops (`offset += 500`) no longer skip rows 100–499.
9. **The agent list metadata projection** dropped keys the UI reads: `filter_policy`, `device_criticality`, `role_risk`, `network_anomaly`. EndpointRisk would have shown "normal" for every agent. They are now included (`filter_policy` ≤16 KB).
10. **Users:** `id` tiebreaker, parameterized LIMIT/OFFSET, cap 100, invalid limit/offset → 400.

## Evidence (all run locally against a disposable PostgreSQL 17 on 127.0.0.1)

- `go vet ./...` and `go test ./...` pass for `shared`, `connection-manager` and `sigma_engine_go`. The real-DB integration tests ran, including:
  - 63-row timestamp ties, forward and backward walks
  - a row inserted mid-walk staying outside the fence
  - a risk-score walk with heavy ties
  - migrations up to 026 with the `indisvalid` check
- Sigma `test/integration` fails three detection tests. These fail identically on an untouched HEAD export, so they predate this work. `test/load` needs a running server.
- `tsc -b` and `vite build` pass.
- ESLint on the changed files: 114 errors vs 125 on the HEAD versions of the same files, with no rule increasing in any file.
- Node unit tests: 24/24.
- Playwright:
  - `test:pagination` (shared fixture, Endpoints, Rules, Events, ActionCenter, SecurityEvents, and the new real Alerts page test)
  - `test:exceptions`
  - `test:alert-details`

  All at 390/1280 in light and dark. `test:alert-details` timed out once right after the other suites, then passed on two consecutive reruns.

### EXPLAIN (ANALYZE, BUFFERS) — 1,000,000 alerts over 58 days, actual repository SQL ([alerts-explain-1m.json](alerts-explain-1m.json))

| Query | ms | Plan |
|---|---:|---|
| created desc, 24h, first page | 0.17 | Index Scan `idx_sigma_alerts_page_created_id` |
| created desc, page 40 / 30d page 400 | 0.16 | same, no Sort |
| risk desc, 24h (first / page 40) | 1.55 / 1.24 | Index Scan on the risk index (named `idx_tmp_risk_id` in the JSON, identical to migration 026) |
| risk desc, 30d | 0.16 | same |
| status=open, 30d | 0.56 | created index |
| agent filter, 30d | 0.16 | `idx_sigma_alerts_page_agent_created_id` |
| severity=critical, 24h | 0.18 | created index (the candidate severity index was **not** used, so it was not added) |

No Seq Scan and no Sort node in any case. Before these fixes: risk 24h took 78 ms and severity 21 ms, both with a Sort.

Earlier Codex measurements (events/alerts 1M, commands/security 125k) are in `sql-benchmark.json`, `command-plans.json` and `security-plans.json`. They showed deep pages going from ~900 ms to <0.4 ms. In that run, alert writes were slower (3.76 s → 4.34 s per 10k inserts) and alert-by-agent first page went 0.69 → 2.04 ms. Those measurements predate migration 026 and were not repeated here.

## Not verified

- No HTTP-level benchmark against the real services, and no production-shaped ingestion load test.
- Behavior on the production database: index build time for `CREATE INDEX CONCURRENTLY` on large tables, and planner choices on real data distributions.
- Docker build with `additional_contexts` (needs Docker Compose ≥ 2.17 with BuildKit) was not run locally.

## Behavior changes to know

- **Alert date ranges** now apply to alert creation time, which is also the "Created" column. Before, they applied to event time.
- **Without `date_from`, the alerts list covers the last 30 days.** The Alerts page always sends its own range, by default 24h.
- **A cursor walk is fenced at the first page's time.** New rows appear through the "new items" banner, the Refresh button, or the first-page refresh. Rows that are updated or deleted during a walk are not snapshotted (accepted by the user).
- **Cursors are HMAC-signed** with a key derived from the DB password. They stay valid across restarts and return 400 when they are tampered with, built for another filter or sort, or offset-based on a keyset list.

## Deploy

```bash
cd ~/EDR-Platform && git pull   # after committing
sudo docker compose build connection-manager sigma-engine dashboard
sudo docker compose up -d --no-deps connection-manager sigma-engine dashboard
sudo docker compose logs --tail=100 connection-manager sigma-engine | grep -iE "migration|pagination index|error"
```

The migrations run at startup: CM 064–069 and Sigma 024–026. Each file is one `CREATE INDEX CONCURRENTLY` statement, so writes are not blocked, but on large tables the first startup waits for the builds. If a build is interrupted, the service refuses to start and names the invalid index. In that case, drop that index (`DROP INDEX CONCURRENTLY <name>`) and restart.

## Round 2 (2026-10-11): page sizes, remaining pages, Endpoint Risk, Audit Logs, Agent Deployment

**Shared**
- Page sizes are now 10 / 25 / 50 / 100 everywhere (`PAGE_SIZES` in `paginationState.ts`, default 25; the server still caps at 100).
- `PaginationControls` gained:
  - a page number ("Page N [of M]")
  - a first-page button
  - "No ⟨label⟩" empty text
- `hooks/useClientPagination.ts`:
  - `useClientPagination` pages full-list (small) responses with URL-synced page and size, a `resetKey`, and clamping when the list shrinks.
  - `useOffsetPageState` serves small limit/offset server lists (limit + 1 probe or total).

**Pages**

| Page | Change |
|---|---|
| Incident Response Playbooks | Playbook list paged on the client; run history paged on the server (limit + 1, offset) |
| Automation Rules | Paged on the client, with an empty state |
| Response Script Library | Search (name, description, command) and paging on the client |
| Detection Exceptions | Paged on the client (search and state filters reset to page 1) |
| System · Signatures | Sync history raised from 50 to 200 and paged. New server-paginated **Signature catalog**: `GET /api/v1/signatures/catalog`, keyset on (version, id), exact SHA-256 or name/family search; the existing `/signatures` and NDJSON feed are untouched |
| Vulnerability Management | Server-side search, filters and paging (it used to load 500 and filter in the browser). Severity chart taken from server stats. Export walks all matching rows (≤5,000). Selection is scoped to the visible page. The server `ORDER BY` gained the `f.id` tiebreaker |
| Fleet Connectivity | Search plus paging on the client. Refresh every 60 s, only while the tab is visible (the attention summary still uses the whole fleet ≤1000) |
| Endpoint details | Forensics events, software inventory, quarantine and activity use the shared pager (fixed sizes of 15/20/10 removed). The dead `_NetworkTab` (offset paging the server rejects) was removed |
| Activity Correlation (renamed from "Temporal fusion") | Fixed the telemetry filter (`eq` → `equals`; it returned 400, so the telemetry section never loaded). Removed the silent 120-row cap. Filters by kind and text, a ±10 min focus around an alert, the shared pager, and a note when 500 rows are loaded per source. `commandsApi.list` reads >100 as multiple pages |

**Endpoint Risk (server)**

`GetEndpointRiskSummary(since)` now counts:
- only active statuses: open, acknowledged, in_progress, investigating (suppressed, resolved and false-positive excluded)
- only alerts active within `window_days` (default 7, 1–90, on `last_seen_at`)
- only endpoints that exist and are not deleted

It also returns hostname, OS, status and metadata.

Covered by the integration test `TestEndpointRiskSummaryPostgres`.

**Endpoint Risk (UI)**
- Removed the hostname merge, which conflated different machines and took the max of averages.
- Removed the 500-agent lookup.
- KPIs come from the same rows as the list.
- Activity window selector, tier and search filters in the URL.
- Cards link to the device page.
- Paging.
- Mobile layout fixed: the hostname used to collapse to zero width at 390px.

**Audit Logs**
- **Migration CM 070** adds `audit_logs.details` (guarded `DO` block, metadata-only). Handler descriptions were built but never stored, so "Extra info" was always empty.
- System audit entries with no user now store `user_id` as NULL. The zero UUID violated the FK and the asynchronous write was lost.
- Duplicate login-success audit removed: the service and the handler both wrote one per sign-in.
- Action groups cover every recorded action.
- UI:
  - real action and resource names and filters
  - IP and result shown in rows
  - the "Session ID" column relabelled "Log ID" (it showed the log id)
  - export covers all matching rows (≤10,000), not just the current page
  - the disabled "Delete logs" button removed
- New `TOKEN_DELETED` actions are written as `token_deleted`; old rows stay filterable.

**Agent Deployment**

Content aligned with the agent and builder code:
- the token is not embedded, only the build/HMAC binding
- the server address is embedded unless skipped
- one build per token
- the install command no longer needs the server flags for normal builds
- correct service name and log path
- `-update`
- offline uninstall uses `-token-stdin` with a token from the device page
- links point to Devices and Tokens

**Verification**
- CM: `go vet` and `go test ./...` pass on real PostgreSQL. This includes the new endpoint risk and audit `details` tests and the migration upgrade to version 70.
- Dashboard:
  - `tsc` and `vite build` pass.
  - Node unit tests: 24/24.
  - Playwright passes: `pagination`, `pagination-pages`, `alerts-pagination`, the new `pagination-more` (6 pages × 390/1280 × light/dark), `detection-exceptions` and `alert-details`.
- ESLint on the changed files shows no rule increase against HEAD.
