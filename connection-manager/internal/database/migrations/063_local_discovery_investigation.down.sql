-- Retain execution history and references when rolling back the built-in policy.
UPDATE automation_rules SET enabled = false, auto_execute = false, updated_at = NOW()
WHERE id = '56956211-fd47-49a1-ad67-7d6586e7d61a';
UPDATE response_playbooks SET enabled = false, updated_at = NOW()
WHERE id = '1e13819d-8d38-44e9-8f74-8ab945e85835';
