package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected")
)

type RefreshTokenRepository struct {
	db *sql.DB
}

func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{
		db: db,
	}
}

// Create menyimpan refresh token pertama dan membuat family_id baru.
func (r *RefreshTokenRepository) Create(
	ctx context.Context,
	userID int,
	tokenHash string,
	expiresAt time.Time,
) error {
	query := `
		INSERT INTO mydream.refresh_tokens (
			user_id,
			family_id,
			token_hash,
			expires_at
		)
		VALUES ($1, uuid_generate_v4(), $2, $3)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userID,
		tokenHash,
		expiresAt,
	)

	return err
}

// Rotate mencabut token lama dan membuat token baru dalam satu transaksi.
func (r *RefreshTokenRepository) Rotate(
	ctx context.Context,
	oldHash string,
	newHash string,
	newExpiresAt time.Time,
) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var (
		userID    int
		familyID  string
		expiresAt time.Time
		revokedAt sql.NullTime
	)

	query := `
		SELECT user_id, family_id::text, expires_at, revoked_at
		FROM mydream.refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`

	err = tx.QueryRowContext(ctx, query, oldHash).Scan(
		&userID,
		&familyID,
		&expiresAt,
		&revokedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrRefreshTokenNotFound
	}

	if err != nil {
		return 0, err
	}

	// Token lama digunakan kembali: cabut seluruh token dalam family.
	if revokedAt.Valid {
		_, err = tx.ExecContext(ctx, `
			UPDATE mydream.refresh_tokens
			SET revoked_at = NOW()
			WHERE family_id = $1
			  AND revoked_at IS NULL
		`, familyID)

		if err != nil {
			return 0, err
		}

		if err := tx.Commit(); err != nil {
			return 0, err
		}

		return 0, ErrRefreshTokenReuse
	}

	if !expiresAt.After(time.Now()) {
		_, err = tx.ExecContext(ctx, `
		UPDATE mydream.refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`, oldHash)

		if err != nil {
			return 0, err
		}

		if err := tx.Commit(); err != nil {
			return 0, err
		}

		return 0, ErrRefreshTokenExpired
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE mydream.refresh_tokens
		SET revoked_at = NOW(),
		    last_used_at = NOW()
		WHERE token_hash = $1
	`, oldHash)

	if err != nil {
		return 0, err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO mydream.refresh_tokens (
			user_id,
			family_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4)
	`, userID, familyID, newHash, newExpiresAt)

	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return userID, nil
}

func (r *RefreshTokenRepository) Revoke(
	ctx context.Context,
	tokenHash string,
) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE mydream.refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`, tokenHash)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return ErrRefreshTokenNotFound
	}

	return nil
}
