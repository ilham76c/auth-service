
-- +goose Up

CREATE TABLE mydream.refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    user_id INTEGER NOT NULL,

    family_id UUID NOT NULL,

    token_hash VARCHAR(64) NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    CONSTRAINT fk_refresh_tokens_user
        FOREIGN KEY (user_id)
        REFERENCES mydream.users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_refresh_tokens_hash
        UNIQUE (token_hash)
);

CREATE INDEX idx_refresh_tokens_user_id
    ON mydream.refresh_tokens(user_id);

CREATE INDEX idx_refresh_tokens_family_id
    ON mydream.refresh_tokens(family_id);

CREATE INDEX idx_refresh_tokens_expires_at
    ON mydream.refresh_tokens(expires_at);

-- +goose Down

DROP TABLE IF EXISTS mydream.refresh_tokens;
