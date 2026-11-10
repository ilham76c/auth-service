package repository

import (
	"context"
	"database/sql"
	"errors"
)

var ErrOAuthAccountNotFound = errors.New("OAuth account not found")

type OAuthRepository struct {
	db *sql.DB
}

func NewOAuthRepository(db *sql.DB) *OAuthRepository {
	return &OAuthRepository{
		db: db,
	}
}

// FindUserIDByProviderUserID mencari user berdasarkan identitas provider.
func (r *OAuthRepository) FindUserIDByProviderUserID(
	ctx context.Context,
	provider string,
	providerUserID string,
) (int, error) {
	var userID int

	query := `
		SELECT user_id
		FROM mydream.oauth_accounts
		WHERE provider = $1
		  AND provider_user_id = $2
		LIMIT 1
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		provider,
		providerUserID,
	).Scan(&userID)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrOAuthAccountNotFound
	}

	if err != nil {
		return 0, err
	}

	return userID, nil
}

// CreateAccountTx menyimpan relasi OAuth dalam transaksi database.
func (r *OAuthRepository) CreateAccountTx(
	ctx context.Context,
	tx *sql.Tx,
	userID int,
	provider string,
	providerUserID string,
) error {
	query := `
		INSERT INTO mydream.oauth_accounts (
			user_id,
			provider,
			provider_user_id
		)
		VALUES ($1, $2, $3)
	`

	_, err := tx.ExecContext(
		ctx,
		query,
		userID,
		provider,
		providerUserID,
	)

	return err
}
