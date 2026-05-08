-- Migration: 053_hash_enrollment_tokens
--
-- Security hardening: enrollment tokens are now stored with a server-side
-- SHA-256 hash in token_hash. The raw value is retained in the token column
-- for the dashboard list view only. All DB lookups by token value now use
-- token_hash, so a DB read leak of token_hash values cannot be used to enroll
-- agents (the agent must present the raw hex token; the server hashes it for
-- comparison).
--
-- Existing rows are backfilled using Postgres's built-in sha256() function.

-- Step 1: Add the column (nullable initially so backfill can run first).
ALTER TABLE public.enrollment_tokens
    ADD COLUMN IF NOT EXISTS token_hash character varying(64);

-- Step 2: Backfill all existing rows.
--   encode(sha256(token::bytea), 'hex') produces the same 64-char lowercase
--   hex string that security.HashToken() produces in Go.
UPDATE public.enrollment_tokens
    SET token_hash = encode(sha256(token::bytea), 'hex')
    WHERE token_hash IS NULL;

-- Step 3: Enforce NOT NULL now that all rows have a hash.
ALTER TABLE public.enrollment_tokens
    ALTER COLUMN token_hash SET NOT NULL;

-- Step 4: Unique index for fast O(1) lookup and collision prevention.
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_tokens_token_hash
    ON public.enrollment_tokens (token_hash);
