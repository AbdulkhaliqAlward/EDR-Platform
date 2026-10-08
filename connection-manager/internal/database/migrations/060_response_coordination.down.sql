DROP INDEX IF EXISTS idx_playbook_executions_trigger;
DROP INDEX IF EXISTS idx_playbook_executions_updated;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS alert_severity;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS alert_title;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS agent_hostname;
