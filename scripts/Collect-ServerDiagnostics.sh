#!/usr/bin/env bash
# Ubuntu/Bash, read-only service diagnostics. No restart, configuration change,
# offset reset, event injection, or endpoint command is performed.
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 1
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Cannot access Docker. Run: sudo bash scripts/Collect-ServerDiagnostics.sh' >&2
  exit 1
fi
diag=$(mktemp -d "${TMPDIR:-/tmp}/MITRAS-Diagnostics-XXXXXXXX") || exit 1
run() {
  local file=$1
  shift
  printf '\n--- %s ---\n' "$file"
  "$@" 2>&1 | tee "$diag/$file.txt"
  local rc=${PIPESTATUS[0]}
  if (( rc != 0 )); then printf 'Diagnostic command exited %s\n' "$rc" | tee -a "$diag/$file.txt"; fi
}
run 00-time date -u --iso-8601=seconds
run 01-revision git log -1 --format='%H %s'
run 02-status git status --short
run 03-services docker compose ps -a
run 04-images docker compose images
run 05-readiness docker compose exec -T connection-manager wget -S -O - http://localhost:8082/readyz
run 06-automation-switch docker compose exec -T connection-manager sh -c 'printf "AUTOMATION_AUTO_EXECUTE=%s\n" "${AUTOMATION_AUTO_EXECUTE:-unset}"'
for service in connection-manager sigma-engine redis kafka postgres; do
  run "logs-$service" docker compose logs --no-color --timestamps --since 15m --tail 350 "$service"
done
run kafka-topics docker compose exec -T kafka kafka-topics --bootstrap-server localhost:9092 --describe --topic events-raw
run kafka-alerts docker compose exec -T kafka kafka-topics --bootstrap-server localhost:9092 --describe --topic alerts
run kafka-consumers docker compose exec -T kafka kafka-consumer-groups --bootstrap-server localhost:9092 --all-groups --describe
# Quoted heredoc and shell arguments keep DB credentials inside the container.
run database-metadata docker compose exec -T postgres sh -c 'exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT now() AS server_utc;
SELECT id, status, last_seen FROM agents ORDER BY last_seen DESC NULLS LAST LIMIT 20;
SELECT id, agent_id, event_type, ts, created_at FROM events ORDER BY ts DESC LIMIT 20;
SELECT id, agent_id, rule_id, severity, status, timestamp, created_at FROM sigma_alerts ORDER BY timestamp DESC LIMIT 20;
SELECT id, enabled, status, severity FROM sigma_rules WHERE id IN
('9f8f4f57-6d7e-4d23-a60a-319f7c36910a','bcc784ca-8489-4b37-938b-b0929df6b996','2b39a76c-d927-443d-93ac-2e8c0770b8cb');
SELECT id, enabled, auto_execute, cooldown_minutes FROM automation_rules WHERE id = '56956211-fd47-49a1-ad67-7d6586e7d61a';
SELECT key, value::jsonb ->> 'enabled' AS enabled, updated_at FROM response_engine_state WHERE key = 'auto_response';
SELECT id, alert_id, agent_id, status, started_at, completed_at, commands_executed, commands_total FROM playbook_executions ORDER BY started_at DESC LIMIT 20;
COMMIT;
SQL
printf '\nDiagnostics saved in: %s\n' "$diag"
