package http

import (
	"github.com/gin-gonic/gin"
	"auth-service/internal/auth"
)

func SetupRouter(authSvc *auth.Service, jwtSvc *auth.JWTService) *gin.Engine {
	r := gin.Default()
	h := NewHandler(authSvc)

	r.POST("/auth/login", h.Login)

	protected := r.Group("/auth")
	protected.Use(AuthMiddleware(jwtSvc))
	protected.GET("/me", h.Me)

	return r
}
