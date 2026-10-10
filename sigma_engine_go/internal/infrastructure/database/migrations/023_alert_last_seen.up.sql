-- Migration 023: sliding alert de-duplication.
-- last_seen_at is the most recent occurrence merged into an open alert; the
-- dedup lookup slides on it (bounded per alert in the application).
ALTER TABLE sigma_alerts ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
UPDATE sigma_alerts SET last_seen_at = GREATEST(timestamp, updated_at) WHERE last_seen_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sigma_alerts_dedup_open
    ON sigma_alerts (agent_id, rule_id, last_seen_at DESC)
    WHERE status NOT IN ('resolved', 'false_positive');
