package repository

import (
	"database/sql"
	"errors"

	"auth-service/internal/user"
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

func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
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
		  AND is_active = TRUE
		  AND deleted_at IS NULL
		LIMIT 1
	`

	var (
		u               user.User
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
