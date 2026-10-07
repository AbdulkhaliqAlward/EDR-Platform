# EDR Platform — Session Handoff Prompt

Paste this to initialize a fresh session.

---

You are continuing work on an **EDR platform** (Windows agent in Go+CGO, Connection Manager in Go, Sigma Engine, Agent Builder, React/TypeScript dashboard, Docker Compose).

## Environment & constraints
- **Repo:** `E:\D-10-5-26\D-10-5-26\graduation_project-final\final-EDR-Platform`
- **Production:** AWS Ubuntu server `~/EDR-Platform`, `sudo docker compose`. Dashboard :30088, gRPC :47051. **Docker is NOT running on the dev machine.**
- **Go toolchain:** downloaded at `%TEMP%\edr-fix\go` (go1.24.13). Build/test with: `GOROOT=<temp>/go`, `GOPATH`/`GOCACHE` under temp, `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`.
- **Full `cmd/agent` cannot build locally** (needs CGO/mingw for ETW; no C compiler here). Only `agent-builder` on the server builds the full agent. Verify agent entry-point code via an isolated non-CGO package type-check (copy the file into a throwaway `cmd/_check/` package + shim with a `main()`).
- **agent-builder bind-mounts `./win_edrAgent`** — pulling source is enough for new agent builds; connection-manager/dashboard need `docker compose up -d --build --no-deps <svc>`.
- **gofmt caveat:** many files are CRLF/unformatted at HEAD. Before claiming a gofmt regression, strip `\r` (`tr -d '\r'`) and compare against HEAD; never mass-reformat files that were already unformatted at HEAD.
- Each enrollment token allows exactly one agent build (keep this).

## Working rules (from user memory `feedback-careful-reliable-edits`)
Every change must be **verified in code (don't trust comments), complete, minimal/scoped, and must not cause new problems.** Build+vet+test every touched package. Never weaken security controls without asking. Report exactly what was and wasn't verified. Load memory files in `C:\Users\onyxv\.claude\projects\E--D-10-5-26-D-10-5-26-graduation-project-final-final-EDR-Platform\memory\` (`MEMORY.md`, `project-edr-platform-context.md`, `feedback-careful-reliable-edits.md`).

**Attribution:** follow the active `<system-reminder>` for commit/PR attribution lines (it has been `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` most recently; use whatever the current reminder states).

## Git state
- Committed: `8ab04f13` (Step B remote-uninstall cleanup).
- **NOT committed** (large, verified, builds/tests green): connection-stream/auth fixes, offline uninstall token (Step A), device soft-delete + agent-ID normalization, command authorization tiers (Stage 1). User has not asked to commit these yet.
- Pending spawned task `task_a81d68c8`: SQL injection in agents-list `sort_by` (`ORDER BY %s` in `agent_repo.go`) — separate, not started.

## Completed this session (all verified: build+vet+test pass; not field-tested on a device)
1. **Stream/auth resilience:** `event_ingestion.go` (transient DB error → `codes.Unavailable`, only `ErrNotFound` → `Unauthenticated`); `interceptors.go` `certValidationError` + `cert_validation_error_test.go`; agent `grpc/client.go` (`canReEnroll`/`waitAfterAuthRejection` — keep retrying stream with 30s→5min backoff instead of dying when no bootstrap token).
2. **Offline uninstall token (Step A):** Ed25519 key in server KeyStore (encrypted at rest), public key embedded in agent via ldflag `EmbeddedUninstallPubKey`. New: `security/uninstall_token.go`, `api/handlers_uninstall_token.go`, agent `internal/uninstalltoken/` (+test, golden-vector cross-module compat), `internal/edrhosts/` (+test), `internal/command/uninstall_offline.go`, `cmd/agent/uninstall.go`. Modified: `keystore.go`, `cmd/server/main.go`, `middleware.go`, `handlers_build.go`, `server.go`, agent `main.go`, `agent-builder/main.go`, dashboard `client.ts` + `EndpointDetail.tsx`. Flow: dashboard mints agent-bound ~30min token (admin RBAC+OTP+audit) → `echo <token> | edr-agent.exe -uninstall -token-stdin` (verifies, schedules SYSTEM stage2 that re-verifies token, stops service, reverts firewall/hosts/sysmon, deletes service/registry/files). Only agents built AFTER this support it.
3. **Agent-ID gotcha:** cert CN/DNS SAN = `agent-<UUID>`; canonical = bare UUID. Use `uninstalltoken.NormalizeAgentID` / `AgentIDFromCertPEM`. `resolveLocalAgentID` reads only registry/cert, never `config.DefaultConfig()` (generates random UUID).
4. **Device soft-delete:** `models/agent.go` `AgentStatusDeleted="deleted"`; `agent_repo.go` (UpdateStatus/UpdateMetrics ignore deleted rows, List/Count hide them); `agent_service.go` `Delete`; `event_ingestion.go` rejects deleted-agent stream; `handlers_agents.go` `DeleteAgent` (409 if agent online, audit, soft delete); dashboard "Remove from dashboard" button+modal.
5. **Command authorization tiers (Problem 1, Stage 1):** server-authoritative over mTLS. Agent `handler.go` `runCmdTier` reads `params["authz_tier"]`: `diagnostic`(strict `allowedDiagnostics`) | `library`(`playbookAllowedCommands`; legacy `from_playbook="true"` maps here) | `custom`(arbitrary). 120s timeout + 512KB cap (`capRunCmdOutput`) + `runcmd_tier_test.go`. Server strips client `authz_tier` (keeps `from_playbook`). `command_type:"custom"` requires `EDR_ALLOW_CUSTOM_COMMANDS=true` (default false, in docker-compose) + admin + reason + OTP(if configured) + audit. `command_service.go`/playbook `engine.go` set `authz_tier=library`. New `GetCommandCapabilities` endpoint; dashboard shows "Custom command (admin)" only when enabled (textarea + required reason).

## Deploy reminder (when user asks)
`sudo docker compose up -d --build --no-deps connection-manager agent-builder dashboard`; rebuild/reinstall agent for agent-side changes; set `EDR_ALLOW_CUSTOM_COMMANDS=true` in `.env` to enable custom commands.

## CURRENT TASK — fix two automation UX problems, THEN do Stage 2 (user paused Stage 2 for these)

**Problem A — can't add actions when creating a playbook.** In `dashboard/src/pages/automation/PlaybooksPage.tsx`, the create form (`confirmCreatePlaybook`, ~line 344-358) has only name/description/category and **hardcodes** `commands: [{ type: 'isolate_network', ... }]`. No action/step selector exists. Add UI to add one or more ordered action steps (command type + its params). `COMMAND_PARAMS` (lines ~22-37) already defines param schemas (terminate_process, quarantine_file, run_cmd, collect_logs, scan_file, update_signatures, collect_forensics, filesystem_timeline). Verify the backend `createPlaybook` payload shape the API expects (`automationApi.createPlaybook` in `client.ts`; server `handlers_automation.go` / `postgres_automation.go` / `models/phase2_models.go`).

**Problem B — automation rule creation demands SQL/Sigma free-text.** In `AutomationRulesPage.tsx` (`confirmCreateRule` ~line 179; form ~line 451-467) the "Trigger Condition (Sigma or SQL-like syntax)" textarea produces `trigger_conditions: { condition: triggerCondition }`. Replace with a **structured, safe, non-expert condition builder** (e.g. dropdowns for field/operator/value: RuleName, Severity, RiskScore, etc.). **Before designing, MUST read the backend matching logic** to produce conditions the engine actually evaluates: `connection-manager/internal/service/automation_service.go` (was about to read this), `internal/repository/postgres_automation.go`, `pkg/api/handlers_automation.go`, `pkg/playbook/engine.go`. Design the form to emit exactly the `trigger_conditions` shape the engine matches on.

**Then Stage 2 — dashboard-managed script library** (deferred): DB migration `058` for a `response_scripts` table (id, name, description, command_type, cmd, timeout, enabled, created_by, timestamps), repo, admin CRUD API (RBAC `responses:execute`/admin), a "run script" endpoint that loads the stored cmd server-side and dispatches at `authz_tier=library`, and dashboard library management + "run script" on device. This lets new commands be added with no agent rebuild (and later lets the client `from_playbook` marker be retired).

Start by reading `automation_service.go` to learn how `trigger_conditions` are evaluated, and inspect the playbook create/list API shape — then propose the structured designs for Problems A and B before implementing.