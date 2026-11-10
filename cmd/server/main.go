package main

import (
	"context"
	"log"

	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/database"
	"auth-service/internal/email"
	"auth-service/internal/repository"
	"auth-service/internal/user"

	httpLayer "auth-service/internal/http"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	cfg := config.Load()

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer db.Close()

	log.Println("PostgreSQL connected successfully")

	jwtSvc := auth.NewJWTService(cfg.JWTSecret)
	googleVerifier, err := auth.NewGoogleVerifier(
		context.Background(),
		cfg.GoogleClientID,
	)
	if err != nil {
		log.Fatalf("Google verifier initialization failed: %v", err)
	}

	oauthRepo := repository.NewOAuthRepository(db)
	userRepo := repository.NewUserRepository(db)
	refreshRepo := repository.NewRefreshTokenRepository(db)
	verificationRepo := repository.NewEmailVerificationRepository(db)

	oauthSvc := auth.NewOAuthService(
		db,
		googleVerifier,
		userRepo,
		oauthRepo,
		refreshRepo,
		jwtSvc,
	)

	smtpSvc := email.NewSMTPService(email.SMTPConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	})

	userSvc := user.NewService(
		db,
		userRepo,
		verificationRepo,
		smtpSvc,
		cfg.AppBaseURL,
	)

	authSvc := auth.NewService(
		jwtSvc,
		userRepo,
		refreshRepo,
	)

	router := httpLayer.SetupRouter(
		authSvc,
		userSvc,
		oauthSvc,
		jwtSvc,
	)

	log.Printf("Auth service running on :%s", cfg.Port)

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
