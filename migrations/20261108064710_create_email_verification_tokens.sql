-- +goose Up

CREATE TABLE mydream.email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_email_verification_user
        FOREIGN KEY (user_id)
        REFERENCES mydream.users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_email_verification_token_hash
        UNIQUE (token_hash)
);

CREATE INDEX idx_email_verification_user_id
    ON mydream.email_verification_tokens(user_id);

CREATE INDEX idx_email_verification_expires_at
    ON mydream.email_verification_tokens(expires_at);


-- +goose Down

DROP TABLE IF EXISTS mydream.email_verification_tokens;