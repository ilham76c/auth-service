package auth

import "errors"

var ErrInvalidCredential = errors.New("invalid credential")

type Service struct {
	jwt *JWTService
}

func NewService(jwt *JWTService) *Service {
	return &Service{jwt: jwt}
}

// Dummy login (nanti ganti DB)
func (s *Service) Login(username, password string) (string, error) {
	if username != "admin" || password != "secret" {
		return "", ErrInvalidCredential
	}

	return s.jwt.GenerateToken("user-123", []string{"admin"})
}
