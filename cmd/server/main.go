package main

import (
	"log"

	"auth-service/internal/auth"
	"auth-service/internal/config"
	httpLayer "auth-service/internal/http"
)

func main() {
	cfg := config.Load()

	jwtSvc := auth.NewJWTService(cfg.JWTSecret)
	authSvc := auth.NewService(jwtSvc)

	r := httpLayer.SetupRouter(authSvc, jwtSvc)

	log.Println("Auth service running on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
