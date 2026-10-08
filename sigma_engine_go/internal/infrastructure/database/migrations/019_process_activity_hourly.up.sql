-- Migration 019: hourly process execution counts for UEBA baselines.
--
-- Replaces the per-execution EMA in process_baselines (which converged to
-- 1.0 regardless of the real rate). One row per (agent, process, UTC hour of
-- the event); baselines are computed from these counts. Retained 15 days.
-- process_baselines is no longer written and can be dropped later.
CREATE TABLE IF NOT EXISTS process_activity_hourly (
    agent_id     TEXT        NOT NULL,
    process_name TEXT        NOT NULL,
    hour_bucket  TIMESTAMPTZ NOT NULL,
    executions   INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, process_name, hour_bucket)
);

CREATE INDEX IF NOT EXISTS idx_process_activity_hourly_agent_hour
    ON process_activity_hourly (agent_id, hour_bucket);
