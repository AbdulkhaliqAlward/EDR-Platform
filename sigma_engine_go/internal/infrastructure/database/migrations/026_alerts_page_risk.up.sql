-- Keep this migration to ONE statement. Concurrent index DDL must run outside a transaction.
-- Serves the risk-score keyset sort (ORDER BY risk_score DESC, id DESC); verified with EXPLAIN on 1M rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sigma_alerts_page_risk_id ON sigma_alerts(risk_score DESC,id DESC);
