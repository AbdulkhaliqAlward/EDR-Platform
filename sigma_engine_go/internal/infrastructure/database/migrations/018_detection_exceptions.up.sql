-- Migration 018: detection exceptions (analyst-managed false-positive
-- suppression, the rule-based equivalent of EDR "rule exceptions").
--
-- An exception suppresses matches of one Sigma rule (or of every rule when
-- rule_id is NULL) on events whose fields satisfy ALL conditions, optionally
-- only on one endpoint. Conditions use Sigma field names (Image, ParentImage,
-- CommandLine, ...) resolved exactly like rule fields, with case-insensitive
-- equals / startswith / endswith / contains. Managed by the Connection
-- Manager (RBAC + audit); read by the sigma engine.
CREATE TABLE IF NOT EXISTS detection_exceptions (
    id              UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    rule_id         VARCHAR(255),
    rule_title      TEXT        NOT NULL DEFAULT '',
    agent_id        VARCHAR(64),
    hostname        TEXT        NOT NULL DEFAULT '',
    conditions      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    reason          TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    expires_at      TIMESTAMPTZ,
    source_alert_id UUID,
    created_by      VARCHAR(255) NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    hit_count       BIGINT      NOT NULL DEFAULT 0,
    last_hit_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_detection_exceptions_enabled ON detection_exceptions (enabled, rule_id);
