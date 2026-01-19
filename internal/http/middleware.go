package http

import (
	"net/http"
	"strings"

	"auth-service/internal/auth"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware(jwt *auth.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := jwt.VerifyToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user", claims)
		c.Next()
	}
}
