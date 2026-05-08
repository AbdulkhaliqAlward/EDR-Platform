-- Migration: 054_add_build_count_to_enrollment_tokens
--
-- Adds build_count to track binary-build consumption separately from
-- enrollment consumption.  One token = exactly one binary build (enforced
-- atomically in Go with WHERE build_count = 0).
-- max_uses / use_count continue to govern how many machines may enroll
-- using the built binary.

ALTER TABLE public.enrollment_tokens
    ADD COLUMN IF NOT EXISTS build_count INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.enrollment_tokens.build_count IS
    'Number of times this token has been used to build an agent binary. '
    'Capped at 1: a token may only produce a single binary build. '
    'Enforced atomically: UPDATE ... WHERE build_count = 0.';
