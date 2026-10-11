-- Single statement: CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_commands_page_issued_id ON commands(issued_at DESC,id DESC);
