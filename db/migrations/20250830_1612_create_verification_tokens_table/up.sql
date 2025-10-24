CREATE TABLE IF NOT EXISTS verification_tokens (
    user_id BIGINT PRIMARY KEY,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);