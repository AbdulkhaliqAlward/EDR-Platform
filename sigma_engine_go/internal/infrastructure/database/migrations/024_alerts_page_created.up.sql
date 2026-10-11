-- Keep this migration to ONE statement. Concurrent index DDL must run outside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sigma_alerts_page_created_id ON sigma_alerts(COALESCE(created_at,timestamp) DESC,id DESC);
