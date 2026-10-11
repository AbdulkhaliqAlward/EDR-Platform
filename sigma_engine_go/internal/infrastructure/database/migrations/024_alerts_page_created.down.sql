-- Keep this migration to ONE statement. Concurrent index DDL must run outside a transaction.
DROP INDEX CONCURRENTLY IF EXISTS idx_sigma_alerts_page_created_id;
