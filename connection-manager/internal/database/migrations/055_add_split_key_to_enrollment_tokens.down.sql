-- Migration: 055_add_split_key_to_enrollment_tokens (DOWN)
ALTER TABLE public.enrollment_tokens
    DROP COLUMN IF EXISTS key_b,
    DROP COLUMN IF EXISTS key_b_served;
