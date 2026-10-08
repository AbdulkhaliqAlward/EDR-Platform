-- Migration 059: server-side response engine
--
-- 1. Playbook executions reference Sigma alerts (sigma_alerts, written by the
--    sigma engine) instead of the legacy, unused "alerts" table. The foreign
--    key to "alerts" made every execution for a real (Sigma) alert fail.
--    alert_id becomes optional (a playbook can be run on an endpoint without
--    an alert); per-step results, trigger source and initiator are recorded.
-- 2. response_alert_inbox: idempotent claim table — each new Sigma alert is
--    evaluated against automation rules exactly once, even across replicas.
-- 3. response_engine_state: first-start marker so enabling the engine never
--    replays automated actions for alerts created before it existed.
-- 4. Seeded playbooks: placeholder paths become alert-bound templates.

-- ── 1. playbook_executions ──────────────────────────────────────────────────
DO $$
DECLARE c record;
BEGIN
    -- Drop every FK from playbook_executions / playbook_suggestions to "alerts"
    -- (looked up by definition, not by assumed constraint name).
    FOR c IN
        SELECT con.conname, rel.relname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE con.contype = 'f'
          AND rel.relname IN ('playbook_executions', 'playbook_suggestions')
          AND con.confrelid = to_regclass('public.alerts')
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', c.relname, c.conname);
    END LOOP;

    -- Replace the status CHECK constraint (adds 'partial').
    FOR c IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.contype = 'c'
          AND con.conrelid = 'playbook_executions'::regclass
          AND pg_get_constraintdef(con.oid) ILIKE '%status%'
    LOOP
        EXECUTE format('ALTER TABLE playbook_executions DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;

ALTER TABLE playbook_executions ALTER COLUMN alert_id DROP NOT NULL;
ALTER TABLE playbook_executions
    ADD CONSTRAINT playbook_executions_status_check
    CHECK (status IN ('pending', 'running', 'completed', 'partial', 'failed', 'cancelled'));

ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS playbook_name       VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS trigger_source      VARCHAR(20)  NOT NULL DEFAULT 'manual';
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS created_by_username VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS steps               JSONB        NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_playbook_executions_alert    ON playbook_executions (alert_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_agent    ON playbook_executions (agent_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_started  ON playbook_executions (started_at DESC);

-- An automation rule fires at most once per alert (duplicate delivery safe).
CREATE UNIQUE INDEX IF NOT EXISTS uq_playbook_executions_alert_rule
    ON playbook_executions (alert_id, rule_id)
    WHERE rule_id IS NOT NULL AND alert_id IS NOT NULL;

-- ── 2. inbox ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_alert_inbox (
    alert_id     UUID PRIMARY KEY,
    claimed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    outcome      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_response_alert_inbox_claimed ON response_alert_inbox (claimed_at);

-- Cooldowns are per (rule, endpoint): a rule that just fired for host A must
-- still respond to host B. Reservation is one conditional upsert (atomic).
CREATE TABLE IF NOT EXISTS automation_rule_cooldowns (
    rule_id       UUID        NOT NULL REFERENCES automation_rules(id) ON DELETE CASCADE,
    agent_id      UUID        NOT NULL,
    last_fired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, agent_id)
);

-- ── 3. engine state ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_engine_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The poller scans recently created Sigma alerts; sigma_alerts belongs to the
-- sigma engine, so only index it when it already exists.
DO $$
BEGIN
    IF to_regclass('public.sigma_alerts') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS idx_sigma_alerts_created_at ON sigma_alerts (created_at);
    END IF;
END $$;

-- ── 4. seeded placeholders → alert-bound templates ──────────────────────────
-- Seeded quarantine/scan steps carried a generic "C:\Windows\Temp" path meant
-- to be overridden by hand; bind them to the alert's file instead.
UPDATE response_playbooks
SET commands = (
        SELECT jsonb_agg(
            CASE
                WHEN step->>'type' IN ('quarantine_file', 'scan_file')
                 AND lower(COALESCE(step->'params'->>'file_path', '')) IN ('c:\windows\temp', 'c:\\windows\\temp')
                THEN jsonb_set(step, '{params,file_path}', '"{{alert.file_path}}"'::jsonb)
                ELSE step
            END
            ORDER BY ord
        )
        FROM jsonb_array_elements(commands) WITH ORDINALITY AS t(step, ord)
    ),
    updated_at = now()
WHERE jsonb_typeof(commands) = 'array'
  AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(commands) s
        WHERE s->>'type' IN ('quarantine_file', 'scan_file')
          AND lower(COALESCE(s->'params'->>'file_path', '')) IN ('c:\windows\temp', 'c:\\windows\\temp')
    );
