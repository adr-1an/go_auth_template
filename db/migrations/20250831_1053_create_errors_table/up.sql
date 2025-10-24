CREATE TABLE IF NOT EXISTS errors (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    machine_id INT NOT NULL,
    name VARCHAR(255),
    message TEXT,
    error TEXT NOT NULL,
    type VARCHAR(64) NOT NULL DEFAULT 'error',
    stack_trace TEXT,
    context JSONB,
    user_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)