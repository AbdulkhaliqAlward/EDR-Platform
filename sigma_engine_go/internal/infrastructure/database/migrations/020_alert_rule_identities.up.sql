ALTER TABLE sigma_alerts ADD COLUMN IF NOT EXISTS related_rule_ids text[] NOT NULL DEFAULT '{}';
