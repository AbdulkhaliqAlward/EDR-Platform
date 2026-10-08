DO $$ BEGIN
 IF to_regclass('public.sigma_alerts') IS NOT NULL THEN
  ALTER TABLE sigma_alerts ADD COLUMN IF NOT EXISTS related_rule_ids text[] NOT NULL DEFAULT '{}';
 END IF;
END $$;
