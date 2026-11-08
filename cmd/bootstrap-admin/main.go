package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"auth-service/internal/config"
	"auth-service/internal/database"
	"auth-service/internal/security"

	"golang.org/x/term"
)

func main() {
	cfg := config.Load()

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer db.Close()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Admin email: ")
	email, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	email = strings.TrimSpace(email)

	fmt.Print("Admin password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	password := string(passwordBytes)

	if len(password) < 12 {
		log.Fatal("Password must contain at least 12 characters")
	}

	if strings.TrimSpace(password) != password {
		log.Fatal("Password must not start or end with whitespace")
	}

	if len(password) > 128 {
		log.Fatal("Password must not exceed 128 bytes")
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		log.Fatalf("Password hashing failed: %v", err)
	}

	ctx := context.Background()

	result, err := db.ExecContext(ctx, `
		UPDATE mydream.users
		SET email = $1,
		    password_hash = $2,
		    is_active = TRUE,
		    modified_at = NOW()
		WHERE id = 1
		  AND deleted_at IS NULL
	`, email, hash)

	if err != nil {
		if isUniqueViolation(err) {
			log.Fatal("Email is already used by another account")
		}
		log.Fatalf("Admin bootstrap failed: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	if rows == 0 {
		log.Fatal("Active admin user with id=1 was not found")
	}

	fmt.Println("Admin account updated successfully (id=1)")
}

func isUniqueViolation(err error) bool {
	var pgErr interface {
		SQLState() string
	}

	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}
