package main

import (
	"log"

	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/database"
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
	authSvc := auth.NewService(jwtSvc)

	router := httpLayer.SetupRouter(authSvc, jwtSvc)

	log.Printf("Auth service running on :%s", cfg.Port)

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}