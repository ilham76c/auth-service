package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"auth-service/internal/model"
)

var ErrUserNotFound = errors.New("user not found")

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	query := `
    SELECT
        id,
        uuid::text,
        username,
        firstname,
        lastname,
        email,
        password_hash,
        email_verified_at,
        is_active
    FROM mydream.users
    WHERE LOWER(email) = LOWER($1)
      AND deleted_at IS NULL
    LIMIT 1
	`

	var (
		u               model.User
		username        sql.NullString
		firstname       sql.NullString
		lastname        sql.NullString
		userEmail       sql.NullString
		passwordHash    sql.NullString
		emailVerifiedAt sql.NullTime
	)

	err := r.db.QueryRow(query, email).Scan(
		&u.ID,
		&u.UUID,
		&username,
		&firstname,
		&lastname,
		&userEmail,
		&passwordHash,
		&emailVerifiedAt,
		&u.IsActive,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	u.Username = username.String
	u.Firstname = firstname.String
	u.Lastname = lastname.String

	if userEmail.Valid {
		u.Email = &userEmail.String
	}

	if passwordHash.Valid {
		u.PasswordHash = &passwordHash.String
	}

	if emailVerifiedAt.Valid {
		u.EmailVerifiedAt = &emailVerifiedAt.Time
	}

	return &u, nil
}

func (r *UserRepository) Create(
	ctx context.Context,
	username string,
	firstname string,
	lastname string,
	email string,
	passwordHash string,
) (*model.User, error) {
	query := `
		INSERT INTO mydream.users (
			username,
			firstname,
			lastname,
			email,
			password_hash,
			is_active
		)
		VALUES ($1, $2, $3, $4, $5, FALSE)
		RETURNING id, uuid::text
	`

	u := &model.User{
		Username:     username,
		Firstname:    firstname,
		Lastname:     lastname,
		Email:        &email,
		PasswordHash: &passwordHash,
		IsActive:     false,
	}

	err := r.db.QueryRowContext(
		ctx,
		query,
		username,
		firstname,
		lastname,
		email,
		passwordHash,
	).Scan(
		&u.ID,
		&u.UUID,
	)

	if err != nil {
		return nil, err
	}

	return u, nil
}

func (r *UserRepository) CreateTx(
	ctx context.Context,
	tx *sql.Tx,
	username string,
	firstname string,
	lastname string,
	email string,
	passwordHash string,
) (*model.User, error) {
	query := `
		INSERT INTO mydream.users (
			username,
			firstname,
			lastname,
			email,
			password_hash,
			is_active
		)
		VALUES ($1, $2, $3, $4, $5, FALSE)
		RETURNING id, uuid::text
	`

	u := &model.User{
		Username:     username,
		Firstname:    firstname,
		Lastname:     lastname,
		Email:        &email,
		PasswordHash: &passwordHash,
		IsActive:     false,
	}

	err := tx.QueryRowContext(
		ctx,
		query,
		username,
		firstname,
		lastname,
		email,
		passwordHash,
	).Scan(&u.ID, &u.UUID)

	if err != nil {
		return nil, err
	}

	return u, nil
}

func (r *UserRepository) FindUnverifiedByEmail(
	ctx context.Context,
	email string,
) (*model.User, error) {
	var (
		u         model.User
		userEmail sql.NullString
		firstname sql.NullString
		lastname  sql.NullString
	)

	err := r.db.QueryRowContext(ctx, `
		SELECT id, uuid::text, username, firstname, lastname, email, is_active
		FROM mydream.users
		WHERE LOWER(email) = LOWER($1)
		  AND email_verified_at IS NULL
		  AND is_active = FALSE
		  AND deleted_at IS NULL
		LIMIT 1
	`, email).Scan(
		&u.ID,
		&u.UUID,
		&u.Username,
		&firstname,
		&lastname,
		&userEmail,
		&u.IsActive,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	u.Firstname = firstname.String
	u.Lastname = lastname.String

	if userEmail.Valid {
		u.Email = &userEmail.String
	}

	return &u, nil
}

func generateOAuthUsername(email string) (string, error) {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(email)), "@", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", errors.New("invalid email address")
	}

	localPart := parts[0]
	var builder strings.Builder

	for _, char := range localPart {
		if (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '_' || char == '-' {
			builder.WriteRune(char)
		}
	}

	base := strings.Trim(builder.String(), "._-")
	if len(base) < 2 {
		base = "user"
	}

	if len(base) > 22 {
		base = base[:22]
	}

	randomBytes := make([]byte, 3)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate username suffix: %w", err)
	}

	return base + "-" + hex.EncodeToString(randomBytes), nil
}

func (r *UserRepository) CreateOAuthUserTx(
	ctx context.Context,
	tx *sql.Tx,
	email string,
	firstname string,
	lastname string,
) (*model.User, error) {
	username, err := generateOAuthUsername(email)
	if err != nil {
		return nil, err
	}

	firstname = strings.TrimSpace(firstname)
	lastname = strings.TrimSpace(lastname)

	if firstname == "" {
		firstname = username
	}

	if lastname == "" {
		lastname = "-"
	}

	query := `
		INSERT INTO mydream.users (
			username,
			firstname,
			lastname,
			email,
			password_hash,
			email_verified_at,
			is_active
		)
		VALUES ($1, $2, $3, $4, NULL, NOW(), TRUE)
		RETURNING id, uuid::text
	`

	u := &model.User{
		Username:     username,
		Firstname:    firstname,
		Lastname:     lastname,
		Email:        &email,
		PasswordHash: nil,
		IsActive:     true,
	}

	err = tx.QueryRowContext(
		ctx,
		query,
		username,
		firstname,
		lastname,
		email,
	).Scan(&u.ID, &u.UUID)

	if err != nil {
		return nil, err
	}

	return u, nil
}
