DROP INDEX IF EXISTS idx_sigma_alerts_dedup_open;
ALTER TABLE sigma_alerts DROP COLUMN IF EXISTS last_seen_at;
