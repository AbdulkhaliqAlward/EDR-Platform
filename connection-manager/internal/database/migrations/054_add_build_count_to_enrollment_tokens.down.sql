-- Migration: 054_add_build_count_to_enrollment_tokens (DOWN)
ALTER TABLE public.enrollment_tokens DROP COLUMN IF EXISTS build_count;
