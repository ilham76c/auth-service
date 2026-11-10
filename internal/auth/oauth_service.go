package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/repository"
)

var ErrOAuthEmailAlreadyRegistered = errors.New(
	"email already registered with another authentication method",
)

var ErrOAuthEmailNotVerified = errors.New(
	"email address has not been verified",
)

type OAuthService struct {
	db          *sql.DB
	google      *GoogleVerifier
	userRepo    *repository.UserRepository
	oauthRepo   *repository.OAuthRepository
	refreshRepo *repository.RefreshTokenRepository
	jwt         *JWTService
}

func NewOAuthService(
	db *sql.DB,
	google *GoogleVerifier,
	userRepo *repository.UserRepository,
	oauthRepo *repository.OAuthRepository,
	refreshRepo *repository.RefreshTokenRepository,
	jwt *JWTService,
) *OAuthService {
	return &OAuthService{
		db:          db,
		google:      google,
		userRepo:    userRepo,
		oauthRepo:   oauthRepo,
		refreshRepo: refreshRepo,
		jwt:         jwt,
	}
}

func (s *OAuthService) LoginWithGoogle(
	ctx context.Context,
	rawIDToken string,
) (*TokenPair, error) {
	identity, err := s.google.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	userID, err := s.oauthRepo.FindUserIDByProviderUserID(
		ctx,
		"google",
		identity.ProviderUserID,
	)

	switch {
	case err == nil:
		// Akun Google sudah terhubung.
	case errors.Is(err, repository.ErrOAuthAccountNotFound):
		// Periksa apakah email sudah dimiliki akun lain.
		existingUser, emailErr := s.userRepo.FindByEmail(identity.Email)

		if emailErr == nil {
			if !existingUser.IsActive {
				return nil, ErrOAuthEmailNotVerified
			}

			return nil, ErrOAuthEmailAlreadyRegistered
		}

		if !errors.Is(emailErr, repository.ErrUserNotFound) {
			return nil, fmt.Errorf("find existing user: %w", emailErr)
		}

		// Buat user dan OAuth account dalam satu transaksi.
		userID, err = s.createGoogleUser(ctx, identity)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("find OAuth account: %w", err)
	}

	return s.issueTokens(ctx, userID)
}

func (s *OAuthService) createGoogleUser(
	ctx context.Context,
	identity *GoogleIdentity,
) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin OAuth transaction: %w", err)
	}
	defer tx.Rollback()

	u, err := s.userRepo.CreateOAuthUserTx(
		ctx,
		tx,
		identity.Email,
		identity.Firstname,
		identity.Lastname,
	)
	if err != nil {
		return 0, fmt.Errorf("create OAuth user: %w", err)
	}

	err = s.oauthRepo.CreateAccountTx(
		ctx,
		tx,
		u.ID,
		"google",
		identity.ProviderUserID,
	)
	if err != nil {
		return 0, fmt.Errorf("create OAuth account: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit OAuth transaction: %w", err)
	}

	return u.ID, nil
}

func (s *OAuthService) issueTokens(
	ctx context.Context,
	userID int,
) (*TokenPair, error) {
	accessToken, err := s.jwt.GenerateToken(
		fmt.Sprint(userID),
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	err = s.refreshRepo.Create(
		ctx,
		userID,
		HashRefreshToken(refreshToken),
		time.Now().Add(RefreshTokenExpiry),
	)
	if err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(TokenExpiry.Seconds()),
	}, nil
}
