-- Keyset activity feeds follow ingestion/update time with UUID tie breakers.
CREATE INDEX IF NOT EXISTS idx_events_prevention_ingested
    ON events (created_at, id)
    WHERE COALESCE(raw->'data'->>'autonomous', raw->>'autonomous') = 'true';
CREATE INDEX IF NOT EXISTS idx_playbook_execution_activity_cursor
    ON playbook_executions (trigger_source, updated_at, id);
