-- Rollback: 057_add_session_version_to_users
ALTER TABLE users DROP COLUMN IF EXISTS session_version;
