-- Keep this migration to ONE statement. Concurrent index DDL must run outside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_page_agent_created_id ON events(agent_id,created_at DESC,id DESC);
