-- Migration: 058_create_response_scripts
-- Dashboard-managed response script library.
--
-- A script is a stored run_cmd command line. The server dispatches it to an
-- agent at the "library" authorization tier (agent playbookAllowedCommands +
-- powershell -File/-EncodedCommand blocks), so new response actions can be
-- added without rebuilding the agent. The command text never comes from the
-- client at run time: POST /agents/:id/commands with script_id loads it here.
--
-- created_by / updated_by store the username (not a users FK) — the same
-- convention commands.metadata uses, because JWT user IDs are not guaranteed
-- to match users.id.

CREATE TABLE IF NOT EXISTS response_scripts (
    id               UUID PRIMARY KEY,
    name             VARCHAR(128) NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    cmd              TEXT NOT NULL,
    timeout_seconds  INTEGER NOT NULL DEFAULT 300 CHECK (timeout_seconds BETWEEN 30 AND 3600),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by       VARCHAR(255) NOT NULL DEFAULT '',
    updated_by       VARCHAR(255) NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Script names are unique (case-insensitive) so analysts can't confuse two scripts.
CREATE UNIQUE INDEX IF NOT EXISTS idx_response_scripts_name_lower ON response_scripts (LOWER(name));
