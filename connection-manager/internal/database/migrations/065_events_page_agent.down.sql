-- Keep this migration to ONE statement. Concurrent index DDL must run outside a transaction.
DROP INDEX CONCURRENTLY IF EXISTS idx_events_page_agent_created_id;
