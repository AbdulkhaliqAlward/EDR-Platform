-- Reverts the additive parts of 059. The foreign keys to the legacy "alerts"
-- table are intentionally NOT restored: executions recorded for Sigma alerts
-- would violate them.
DROP INDEX IF EXISTS uq_playbook_executions_alert_rule;
DROP INDEX IF EXISTS idx_playbook_executions_alert;
DROP INDEX IF EXISTS idx_playbook_executions_agent;
DROP INDEX IF EXISTS idx_playbook_executions_started;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS playbook_name;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS trigger_source;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS created_by_username;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS steps;
ALTER TABLE playbook_executions DROP COLUMN IF EXISTS updated_at;
DROP TABLE IF EXISTS response_alert_inbox;
DROP TABLE IF EXISTS automation_rule_cooldowns;
DROP TABLE IF EXISTS response_engine_state;
DROP INDEX IF EXISTS idx_sigma_alerts_created_at;
