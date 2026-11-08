package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrVerificationTokenNotFound = errors.New("verification token not found")
	ErrVerificationTokenExpired  = errors.New("verification token expired")
	ErrVerificationTokenUsed     = errors.New("verification token already used")
)

type EmailVerificationRepository struct {
	db *sql.DB
}

func NewEmailVerificationRepository(db *sql.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{db: db}
}

func (r *EmailVerificationRepository) Create(
	ctx context.Context,
	userID int,
	tokenHash string,
	expiresAt time.Time,
) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO mydream.email_verification_tokens (
			user_id, token_hash, expires_at
		)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)

	return err
}

func (r *EmailVerificationRepository) Verify(
	ctx context.Context,
	tokenHash string,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		userID    int
		expiresAt time.Time
		usedAt    sql.NullTime
	)

	err = tx.QueryRowContext(ctx, `
		SELECT user_id, expires_at, used_at
		FROM mydream.email_verification_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash).Scan(&userID, &expiresAt, &usedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrVerificationTokenNotFound
	}
	if err != nil {
		return err
	}

	if usedAt.Valid {
		return ErrVerificationTokenUsed
	}

	if !expiresAt.After(time.Now()) {
		return ErrVerificationTokenExpired
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE mydream.email_verification_tokens
		SET used_at = NOW()
		WHERE token_hash = $1
	`, tokenHash)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE mydream.users
		SET email_verified_at = NOW(),
		    is_active = TRUE,
		    modified_at = NOW()
		WHERE id = $1
		  AND deleted_at IS NULL
	`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *EmailVerificationRepository) CreateTx(
	ctx context.Context,
	tx *sql.Tx,
	userID int,
	tokenHash string,
	expiresAt time.Time,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO mydream.email_verification_tokens (
			user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)

	return err
}
