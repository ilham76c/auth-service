package config

import (
	"log"
	"os"
)

type Config struct {
	JWTSecret string
}

func Load() *Config {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	return &Config{
		JWTSecret: secret,
	}
}
