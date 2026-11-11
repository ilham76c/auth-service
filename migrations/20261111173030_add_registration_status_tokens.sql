
-- +goose Up

CREATE TABLE mydream.registration_status_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_registration_status_user
        FOREIGN KEY (user_id)
        REFERENCES mydream.users(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_registration_status_user_id
    ON mydream.registration_status_tokens(user_id);

CREATE INDEX idx_registration_status_expires_at
    ON mydream.registration_status_tokens(expires_at);


-- +goose Down

DROP TABLE IF EXISTS mydream.registration_status_tokens;
