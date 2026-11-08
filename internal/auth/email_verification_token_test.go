package auth

import "testing"

func TestGenerateEmailVerificationToken(t *testing.T) {
	token1, err := GenerateEmailVerificationToken()
	if err != nil {
		t.Fatal(err)
	}

	token2, err := GenerateEmailVerificationToken()
	if err != nil {
		t.Fatal(err)
	}

	if token1 == token2 {
		t.Fatal("expected unique verification tokens")
	}

	if len(token1) == 0 {
		t.Fatal("verification token must not be empty")
	}
}

func TestHashEmailVerificationToken(t *testing.T) {
	token := "example-verification-token"

	hash1 := HashEmailVerificationToken(token)
	hash2 := HashEmailVerificationToken(token)

	if hash1 != hash2 {
		t.Fatal("same token should produce same hash")
	}

	if hash1 == token {
		t.Fatal("hash must differ from original token")
	}
}
