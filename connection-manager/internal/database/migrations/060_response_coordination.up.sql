-- Migration 060: response coordination and analyst visibility
--
-- Executions carry the endpoint hostname and the alert title/severity so the
-- dashboard can notify analysts about automated responses without extra
-- lookups. updated_at is indexed for the "changes since" notification feed.
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS agent_hostname VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS alert_title    TEXT         NOT NULL DEFAULT '';
ALTER TABLE playbook_executions ADD COLUMN IF NOT EXISTS alert_severity VARCHAR(20)  NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_playbook_executions_updated ON playbook_executions (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_trigger ON playbook_executions (trigger_source, updated_at DESC);
