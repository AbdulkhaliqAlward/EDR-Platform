-- 051_cert_lifecycle: Add CRL table and last_seen_at to certificates.
-- The certificates table already exists with all needed columns except last_seen_at.

-- 1. Add last_seen_at column to existing certificates table.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

-- 2. Create certificate_revocation_list table for DB-backed CRL.
CREATE TABLE IF NOT EXISTS certificate_revocation_list (
    serial_number TEXT PRIMARY KEY,
    fingerprint   TEXT NOT NULL DEFAULT '',
    revoked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_crl_fingerprint ON certificate_revocation_list (fingerprint);

-- 3. Add certificate_pem column for full PEM storage (public_key currently stores PEM but column name is misleading).
-- No rename needed: the existing public_key column already stores PEM-encoded cert. This is fine.
