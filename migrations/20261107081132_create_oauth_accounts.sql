
-- +goose Up

CREATE TABLE mydream.oauth_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    user_id INTEGER NOT NULL,

    provider VARCHAR(30) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ,

    CONSTRAINT fk_oauth_accounts_user
        FOREIGN KEY (user_id)
        REFERENCES mydream.users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_oauth_accounts_provider_user
        UNIQUE (provider, provider_user_id),

    CONSTRAINT uq_oauth_accounts_user_provider
        UNIQUE (user_id, provider),

    CONSTRAINT ck_oauth_accounts_provider
        CHECK (provider IN ('google', 'github'))
);

CREATE INDEX idx_oauth_accounts_user_id
    ON mydream.oauth_accounts(user_id);

-- +goose Down

DROP TABLE IF EXISTS mydream.oauth_accounts;
