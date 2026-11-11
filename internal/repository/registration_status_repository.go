package repository

import (
	"context"
	"database/sql"
	"time"
)

type RegistrationStatusRepository struct {
	db *sql.DB
}

func NewRegistrationStatusRepository(db *sql.DB) *RegistrationStatusRepository {
	return &RegistrationStatusRepository{
		db: db,
	}
}

func (r *RegistrationStatusRepository) CreateTx(
	ctx context.Context,
	tx *sql.Tx,
	userID int,
	tokenHash string,
	expiresAt time.Time,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO mydream.registration_status_tokens (
			user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)

	return err
}

func (r *RegistrationStatusRepository) IsVerified(
	ctx context.Context,
	tokenHash string,
) (bool, error) {
	var verified bool

	err := r.db.QueryRowContext(ctx, `
		SELECT u.email_verified_at IS NOT NULL
		FROM mydream.registration_status_tokens rst
		JOIN mydream.users u ON u.id = rst.user_id
		WHERE rst.token_hash = $1
		  AND rst.expires_at > NOW()
		  AND u.deleted_at IS NULL
	`, tokenHash).Scan(&verified)

	if err == sql.ErrNoRows {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return verified, nil
}
