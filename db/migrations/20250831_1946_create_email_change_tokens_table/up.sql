CREATE TABLE IF NOT EXISTS email_change_tokens (
    user_id BIGINT PRIMARY KEY,
    token_hash BYTEA NOT NULL,
    new_email VARCHAR(254) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);