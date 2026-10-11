-- Single statement: CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_page_created_id ON security_events(created_at DESC,id DESC);
