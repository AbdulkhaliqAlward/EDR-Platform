-- Where each agent connects from (as seen by the server) and how far its
-- clock is from the server's. Kept apart from agents so the heavily used
-- agents queries are unchanged. Written from heartbeats.
CREATE TABLE IF NOT EXISTS agent_network_context (
    agent_id          UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    public_ip         TEXT,
    network_scope     TEXT NOT NULL DEFAULT 'unknown', -- public | private | unknown
    country_code      TEXT,
    country           TEXT,
    region            TEXT,
    city              TEXT,
    geo_source        TEXT,
    geo_resolved_at   TIMESTAMPTZ,
    clock_offset_ms   BIGINT,          -- server time minus agent time
    clock_measured_at TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
