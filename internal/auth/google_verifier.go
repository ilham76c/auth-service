package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	ErrInvalidGoogleToken    = errors.New("invalid Google ID token")
	ErrUnverifiedGoogleEmail = errors.New("Google email is not verified")
)

type GoogleIdentity struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Firstname      string
	Lastname       string
}

type GoogleVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func NewGoogleVerifier(
	ctx context.Context,
	clientID string,
) (*GoogleVerifier, error) {
	if clientID == "" {
		return nil, errors.New("Google client ID is required")
	}

	provider, err := oidc.NewProvider(
		ctx,
		"https://accounts.google.com",
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Google OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &GoogleVerifier{
		verifier: verifier,
	}, nil
}

func (g *GoogleVerifier) Verify(
	ctx context.Context,
	rawIDToken string,
) (*GoogleIdentity, error) {
	if rawIDToken == "" {
		return nil, ErrInvalidGoogleToken
	}

	idToken, err := g.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGoogleToken, err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Firstname     string `json:"given_name"`
		Lastname      string `json:"family_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: unable to decode claims", ErrInvalidGoogleToken)
	}

	if claims.Email == "" || idToken.Subject == "" {
		return nil, ErrInvalidGoogleToken
	}

	if !claims.EmailVerified {
		return nil, ErrUnverifiedGoogleEmail
	}

	return &GoogleIdentity{
		ProviderUserID: idToken.Subject,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Name:           claims.Name,
		Firstname:      claims.Firstname,
		Lastname:       claims.Lastname,
	}, nil
}
