-- 052_security_events.up.sql
-- Persistent security audit log — one row per security-relevant event.

CREATE TABLE IF NOT EXISTS security_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT        NOT NULL,           -- login_success, login_failed, cert_revoked, …
    severity    TEXT        NOT NULL,           -- info, warning, critical
    actor_id    UUID,                           -- user/agent UUID (nullable for system events)
    actor_name  TEXT        NOT NULL DEFAULT '', -- username or agent hostname
    target_id   UUID,                           -- affected resource UUID (nullable)
    target_type TEXT        NOT NULL DEFAULT '', -- user, certificate, agent, session
    ip_address  TEXT        NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT '',
    description TEXT        NOT NULL DEFAULT '',
    metadata    JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_event_type  ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity    ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_security_events_actor_id    ON security_events (actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_created_at  ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_target_id   ON security_events (target_id) WHERE target_id IS NOT NULL;
