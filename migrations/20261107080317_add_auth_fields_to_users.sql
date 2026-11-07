
-- +goose Up

ALTER TABLE mydream.users
    ADD COLUMN email VARCHAR(255),
    ADD COLUMN password_hash TEXT,
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;

-- Email harus unik untuk setiap akun aktif.
-- Perbandingan tidak membedakan huruf besar dan kecil.
CREATE UNIQUE INDEX uq_users_email_active
    ON mydream.users (LOWER(email))
    WHERE email IS NOT NULL
      AND deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS mydream.uq_users_email_active;

ALTER TABLE mydream.users
    DROP COLUMN IF EXISTS is_active,
    DROP COLUMN IF EXISTS email_verified_at,
    DROP COLUMN IF EXISTS password_hash,
    DROP COLUMN IF EXISTS email;
