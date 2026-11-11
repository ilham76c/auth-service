package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

const RegistrationStatusTokenExpiry = 30 * time.Minute

func GenerateRegistrationStatusToken() (string, error) {
	tokenBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate registration status token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func HashRegistrationStatusToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
