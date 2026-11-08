package auth

import "testing"

func TestGenerateRefreshToken(t *testing.T) {
	token1, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}

	token2, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}

	if token1 == token2 {
		t.Fatal("expected unique refresh tokens")
	}

	if len(token1) == 0 {
		t.Fatal("refresh token must not be empty")
	}
}

func TestHashRefreshToken(t *testing.T) {
	token := "example-refresh-token"

	hash1 := HashRefreshToken(token)
	hash2 := HashRefreshToken(token)

	if hash1 != hash2 {
		t.Fatal("same token should produce same hash")
	}

	if hash1 == token {
		t.Fatal("hash must differ from original token")
	}
}
