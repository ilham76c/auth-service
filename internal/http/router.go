package http

import (
	"auth-service/internal/auth"
	"auth-service/internal/user"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRouter(
	authSvc *auth.Service,
	userSvc *user.Service,
	oauthSvc *auth.OAuthService,
	jwtSvc *auth.JWTService,
) *gin.Engine {
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:3000",
		},
		AllowMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"OPTIONS",
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
		},
	}))

	// Disable trusted proxies for local development.
	if err := r.SetTrustedProxies(nil); err != nil {
		panic(err)
	}

	h := NewHandler(authSvc, userSvc, oauthSvc)

	r.POST("/auth/register", h.Register)
	r.POST("/auth/verify-email", h.VerifyEmail)
	r.POST("/auth/resend-verification", h.ResendVerification)
	r.POST("/auth/login", h.Login)
	r.POST("/auth/oauth", h.OAuthLogin)
	r.POST("/auth/refresh", h.Refresh)
	r.POST("/auth/logout", h.Logout)

	protected := r.Group("/auth")
	protected.Use(AuthMiddleware(jwtSvc))
	protected.GET("/me", h.Me)

	return r
}
