CREATE TABLE IF NOT EXISTS detection_exception_hit_batches(id uuid PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS detection_exception_hit_batches_created ON detection_exception_hit_batches(created_at);
