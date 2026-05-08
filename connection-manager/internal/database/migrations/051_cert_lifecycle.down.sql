DROP TABLE IF EXISTS certificate_revocation_list;
ALTER TABLE certificates DROP COLUMN IF EXISTS last_seen_at;
