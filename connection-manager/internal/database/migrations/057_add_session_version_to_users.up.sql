-- Migration: 057_add_session_version_to_users
-- Adds session_version to the users table for stateful concurrent-session invalidation.
--
-- Design: One integer per user (not per session). When a new login or logout occurs,
-- the server increments session_version. Every access token embeds the version (sv claim)
-- at issuance time. The auth middleware compares sv in the token against the DB value;
-- a mismatch means the token was issued by an older session and is immediately rejected.
--
-- Performance: The version column is a single integer read. In practice it is fetched
-- as part of the existing user lookup that the auth middleware already performs, so
-- there is zero additional query overhead when combined with that read.

ALTER TABLE users
    ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN users.session_version IS
    'Monotonically incrementing counter. Embedded as sv claim in JWT access tokens. '
    'Incremented on every new login and logout. Tokens carrying a stale version are '
    'rejected immediately by AuthMiddleware without waiting for JWT expiry.';
