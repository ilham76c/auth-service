package auth

import "testing"

func TestHashPassword(t *testing.T) {
	password := "MySecretPassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == password {
		t.Fatal("password must not be stored as plaintext")
	}

	if hash == "" {
		t.Fatal("password hash must not be empty")
	}

	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}

	if !valid {
		t.Fatal("expected password to be valid")
	}
}

func TestVerifyPasswordWrongPassword(t *testing.T) {
	hash, err := HashPassword("CorrectPassword123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	valid, err := VerifyPassword("WrongPassword123!", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}

	if valid {
		t.Fatal("expected password to be invalid")
	}
}

func TestHashPasswordProducesDifferentHashes(t *testing.T) {
	password := "MySecretPassword123!"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if hash1 == hash2 {
		t.Fatal("expected different hashes because salts should be random")
	}
}
