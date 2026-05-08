-- Migration: 055_add_split_key_to_enrollment_tokens
--
-- Split-key architecture: the 32-byte AES decryption key is split into two
-- 16-byte halves.  key_a is baked into the agent binary via ldflag; key_b is
-- stored here and served exactly once over the /api/v1/agent/key-half endpoint.
--
-- Security properties:
--   * Binary alone  → attacker has key_a but NOT key_b → cannot decrypt token.
--   * DB alone       → attacker has key_b but NOT key_a → cannot decrypt token.
--   * key_b is set to NULL immediately after being served, making it permanently
--     irrecoverable from the DB — even a full DB dump post-enrollment reveals nothing.
--   * key_b_served = TRUE is the permanent audit marker (never reset).

ALTER TABLE public.enrollment_tokens
    ADD COLUMN IF NOT EXISTS key_b        TEXT    DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS key_b_served BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN public.enrollment_tokens.key_b IS
    'Hex-encoded 16-byte second half of the AES-256 split key.  '
    'NULLed permanently after being served once via POST /api/v1/agent/key-half.  '
    'NULL after serving is the security invariant: the key half cannot be replayed.';

COMMENT ON COLUMN public.enrollment_tokens.key_b_served IS
    'TRUE once key_b has been served to an agent.  Never reset.  '
    'Allows forensic queries: SELECT * FROM enrollment_tokens WHERE key_b_served = TRUE.';
