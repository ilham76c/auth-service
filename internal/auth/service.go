package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/repository"
)

var ErrInvalidCredential = errors.New("invalid credential")

const RefreshTokenExpiry = 30 * 24 * time.Hour

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type Service struct {
	jwt         *JWTService
	userRepo    *repository.UserRepository
	refreshRepo *repository.RefreshTokenRepository
}

func NewService(
	jwt *JWTService,
	userRepo *repository.UserRepository,
	refreshRepo *repository.RefreshTokenRepository,
) *Service {
	return &Service{
		jwt:         jwt,
		userRepo:    userRepo,
		refreshRepo: refreshRepo,
	}
}

func (s *Service) Login(
	ctx context.Context,
	email string,
	password string,
) (*TokenPair, error) {
	u, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredential
	}

	if u.PasswordHash == nil {
		return nil, ErrInvalidCredential
	}

	valid, err := VerifyPassword(password, *u.PasswordHash)
	if err != nil || !valid {
		return nil, ErrInvalidCredential
	}

	accessToken, err := s.jwt.GenerateToken(
		fmt.Sprint(u.ID),
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	err = s.refreshRepo.Create(
		ctx,
		u.ID,
		HashRefreshToken(refreshToken),
		time.Now().Add(RefreshTokenExpiry),
	)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(TokenExpiry.Seconds()),
	}, nil
}

func (s *Service) Refresh(
	ctx context.Context,
	oldRefreshToken string,
) (*TokenPair, error) {
	if oldRefreshToken == "" {
		return nil, ErrInvalidCredential
	}

	newRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	newRefreshHash := HashRefreshToken(newRefreshToken)
	oldRefreshHash := HashRefreshToken(oldRefreshToken)

	userID, err := s.refreshRepo.Rotate(
		ctx,
		oldRefreshHash,
		newRefreshHash,
		time.Now().Add(RefreshTokenExpiry),
	)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwt.GenerateToken(
		fmt.Sprint(userID),
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(TokenExpiry.Seconds()),
	}, nil
}

func (s *Service) Logout(
	ctx context.Context,
	refreshToken string,
) error {
	if refreshToken == "" {
		return ErrInvalidCredential
	}

	tokenHash := HashRefreshToken(refreshToken)

	return s.refreshRepo.Revoke(ctx, tokenHash)
}
