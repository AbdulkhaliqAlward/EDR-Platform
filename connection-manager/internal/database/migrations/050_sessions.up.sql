-- 050_sessions: Server-side session tracking for refresh token rotation
-- and single active session enforcement.
CREATE TABLE IF NOT EXISTS sessions (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT        NOT NULL,              -- SHA-256 hex of opaque token
    access_jti         TEXT        NOT NULL DEFAULT '',    -- JTI of the current access token
    ip_address         TEXT        NOT NULL DEFAULT '',
    user_agent         TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,                       -- NULL = active
    revoke_reason      TEXT        DEFAULT ''              -- logout | superseded | rotation | security | admin
);

-- Fast lookups by refresh token hash (used on every /auth/refresh call).
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions (refresh_token_hash);

-- Fast lookups for single-session enforcement and revoke-all.
CREATE INDEX IF NOT EXISTS idx_sessions_user_id_active ON sessions (user_id) WHERE revoked_at IS NULL;

-- Fast lookups by access JTI (used on /auth/logout).
CREATE INDEX IF NOT EXISTS idx_sessions_access_jti ON sessions (access_jti) WHERE revoked_at IS NULL;
