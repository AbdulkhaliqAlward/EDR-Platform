-- Rollback: 056_bind_build_id_to_enrollment_tokens
--
-- Restores the schema to the state after migration 055.
-- Re-adds key_b and key_b_served; drops build_id.

DROP INDEX IF EXISTS public.uq_enrollment_tokens_build_id;

ALTER TABLE public.enrollment_tokens
    DROP COLUMN IF EXISTS build_id;

ALTER TABLE public.enrollment_tokens
    ADD COLUMN IF NOT EXISTS key_b        TEXT    DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS key_b_served BOOLEAN NOT NULL DEFAULT FALSE;
