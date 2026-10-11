-- Audit entries carry a human-readable description (AuditLog.Details, e.g.
-- "playbook X run on agent Y") that was built by every handler but never
-- stored, so "Extra info" was always empty. Nullable with no default: a
-- metadata-only change that does not rewrite the table (or its partitions).
DO $$
BEGIN
    IF to_regclass('audit_logs') IS NOT NULL THEN
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT;
    END IF;
END $$;
