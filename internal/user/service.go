package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/email"
	"auth-service/internal/repository"
	"auth-service/internal/security"

	"github.com/jackc/pgx/v5/pgconn"
)

var usernameRegex = regexp.MustCompile(
	`^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]$`,
)

var (
	ErrInvalidRegistration       = errors.New("invalid registration")
	ErrEmailAlreadyExists        = errors.New("email already registered")
	ErrUsernameAlreadyExists     = errors.New("username already taken")
	ErrVerificationTokenNotFound = repository.ErrVerificationTokenNotFound
	ErrVerificationTokenExpired  = repository.ErrVerificationTokenExpired
	ErrVerificationTokenUsed     = repository.ErrVerificationTokenUsed
	ErrEmailAlreadyVerified      = errors.New("email already verified")
)

const EmailVerificationExpiry = 24 * time.Hour

func mapRegistrationError(err error) error {
	var pgErr *pgconn.PgError

	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return err
	}

	switch pgErr.ConstraintName {
	case "users_username_key":
		return ErrUsernameAlreadyExists
	case "uq_users_email_active":
		return ErrEmailAlreadyExists
	default:
		return err
	}
}

type RegistrationInput struct {
	Username  string
	Firstname string
	Lastname  string
	Email     string
	Password  string
}

type RegistrationResult struct {
	UserID                  int
	UUID                    string
	EmailVerificationToken  string
	RegistrationStatusToken string
}

type Service struct {
	db               *sql.DB
	userRepo         *repository.UserRepository
	verificationRepo *repository.EmailVerificationRepository
	statusRepo       *repository.RegistrationStatusRepository
	emailService     email.Service
	appBaseURL       string
}

func NewService(
	db *sql.DB,
	userRepo *repository.UserRepository,
	verificationRepo *repository.EmailVerificationRepository,
	statusRepo *repository.RegistrationStatusRepository,
	emailService email.Service,
	appBaseURL string,
) *Service {
	return &Service{
		db:               db,
		userRepo:         userRepo,
		verificationRepo: verificationRepo,
		statusRepo:       statusRepo,
		emailService:     emailService,
		appBaseURL:       appBaseURL,
	}
}

func (s *Service) Register(
	ctx context.Context,
	input RegistrationInput,
) (*RegistrationResult, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.Firstname = strings.TrimSpace(input.Firstname)
	input.Lastname = strings.TrimSpace(input.Lastname)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if !usernameRegex.MatchString(input.Username) {
		return nil, ErrInvalidRegistration
	}

	if input.Username == "" ||
		input.Firstname == "" ||
		input.Lastname == "" ||
		input.Email == "" ||
		len(input.Password) < 12 ||
		len(input.Password) > 128 {
		return nil, ErrInvalidRegistration
	}

	if _, err := mail.ParseAddress(input.Email); err != nil {
		return nil, ErrInvalidRegistration
	}

	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	u, err := s.userRepo.CreateTx(
		ctx,
		tx,
		input.Username,
		input.Firstname,
		input.Lastname,
		input.Email,
		passwordHash,
	)
	if err != nil {
		return nil, mapRegistrationError(err)
	}

	token, err := auth.GenerateEmailVerificationToken()
	if err != nil {
		return nil, err
	}

	err = s.verificationRepo.CreateTx(
		ctx,
		tx,
		u.ID,
		auth.HashEmailVerificationToken(token),
		time.Now().Add(EmailVerificationExpiry),
	)
	if err != nil {
		return nil, err
	}

	// Generate registration status token.
	statusToken, err := auth.GenerateRegistrationStatusToken()
	if err != nil {
		return nil, err
	}

	// Store only the token hash.
	err = s.statusRepo.CreateTx(
		ctx,
		tx,
		u.ID,
		auth.HashRegistrationStatusToken(statusToken),
		time.Now().Add(auth.RegistrationStatusTokenExpiry),
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	verificationURL := email.BuildVerificationURL(
		s.appBaseURL,
		token,
	)

	if err := s.emailService.SendVerificationEmail(
		input.Email,
		verificationURL,
	); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	return &RegistrationResult{
		UserID:                  u.ID,
		UUID:                    u.UUID,
		RegistrationStatusToken: statusToken,
	}, nil
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)

	if token == "" {
		return ErrInvalidRegistration
	}

	tokenHash := auth.HashEmailVerificationToken(token)

	return s.verificationRepo.Verify(ctx, tokenHash)
}

func (s *Service) ResendVerification(
	ctx context.Context,
	emailAddress string,
) error {
	emailAddress = strings.ToLower(strings.TrimSpace(emailAddress))

	if _, err := mail.ParseAddress(emailAddress); err != nil {
		return ErrInvalidRegistration
	}

	u, err := s.userRepo.FindUnverifiedByEmail(ctx, emailAddress)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			// Do not reveal whether an email exists.
			return nil
		}
		return err
	}

	token, err := auth.GenerateEmailVerificationToken()
	if err != nil {
		return err
	}

	err = s.verificationRepo.ReplacePending(
		ctx,
		u.ID,
		auth.HashEmailVerificationToken(token),
		time.Now().Add(EmailVerificationExpiry),
	)
	if err != nil {
		return err
	}

	verificationURL := email.BuildVerificationURL(
		s.appBaseURL,
		token,
	)

	if err := s.emailService.SendVerificationEmail(
		emailAddress,
		verificationURL,
	); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

func (s *Service) IsEmailVerified(
	ctx context.Context,
	email string,
) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if email == "" {
		return false, ErrInvalidRegistration
	}

	return s.userRepo.IsEmailVerified(ctx, email)
}

func (s *Service) IsRegistrationStatusVerified(
	ctx context.Context,
	token string,
) (bool, error) {
	if strings.TrimSpace(token) == "" {
		return false, ErrInvalidRegistration
	}

	tokenHash := auth.HashRegistrationStatusToken(token)

	return s.statusRepo.IsVerified(ctx, tokenHash)
}
