-- Migration: 053_hash_enrollment_tokens (DOWN)
DROP INDEX IF EXISTS public.idx_enrollment_tokens_token_hash;
ALTER TABLE public.enrollment_tokens DROP COLUMN IF EXISTS token_hash;
