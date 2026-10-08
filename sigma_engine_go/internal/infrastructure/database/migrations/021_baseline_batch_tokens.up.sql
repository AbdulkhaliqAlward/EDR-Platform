CREATE TABLE IF NOT EXISTS baseline_count_batches (
 id uuid PRIMARY KEY,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS baseline_count_batches_created ON baseline_count_batches(created_at);
CREATE INDEX IF NOT EXISTS process_activity_hourly_hour ON process_activity_hourly(hour_bucket);
