package http

import (
	"errors"
	"net/http"

	"auth-service/internal/auth"
	"auth-service/internal/user"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	auth *auth.Service
	user *user.Service
}

func NewHandler(authSvc *auth.Service, userSvc *user.Service) *Handler {
	return &Handler{
		auth: authSvc,
		user: userSvc,
	}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	tokens, err := h.auth.Login(
		c.Request.Context(),
		req.Email,
		req.Password,
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    tokens.ExpiresIn,
	})
}

func (h *Handler) Me(c *gin.Context) {
	claims, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized",
		})
		return
	}

	userClaims, ok := claims.(*auth.Claims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token claims",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": userClaims.Subject,
		"roles":   userClaims.Roles,
	})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	tokens, err := h.auth.Refresh(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    tokens.ExpiresIn,
	})
}

func (h *Handler) Logout(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	err := h.auth.Logout(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

type RegisterRequest struct {
	Username  string `json:"username" binding:"required"`
	Firstname string `json:"firstname" binding:"required"`
	Lastname  string `json:"lastname" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	result, err := h.user.Register(
		c.Request.Context(),
		user.RegistrationInput{
			Username:  req.Username,
			Firstname: req.Firstname,
			Lastname:  req.Lastname,
			Email:     req.Email,
			Password:  req.Password,
		},
	)

	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidRegistration):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})

		case errors.Is(err, user.ErrUsernameAlreadyExists),
			errors.Is(err, user.ErrEmailAlreadyExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": err.Error(),
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Registration failed",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful. Please check your email to verify your account.",
		"user_id": result.UserID,
		"uuid":    result.UUID,
	})
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	err := h.user.VerifyEmail(
		c.Request.Context(),
		req.Token,
	)

	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{
			"message": "Email verified successfully",
		})

	case errors.Is(err, user.ErrVerificationTokenNotFound),
		errors.Is(err, user.ErrVerificationTokenExpired),
		errors.Is(err, user.ErrVerificationTokenUsed):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid, expired, or already used verification token",
		})

	case errors.Is(err, user.ErrInvalidRegistration):
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Verification token is required",
		})

	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Email verification failed",
		})
	}
}

type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *Handler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	err := h.user.ResendVerification(
		c.Request.Context(),
		req.Email,
	)

	if errors.Is(err, user.ErrInvalidRegistration) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email address",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to process verification request",
		})
		return
	}

	// Generic response to prevent account enumeration.
	c.JSON(http.StatusOK, gin.H{
		"message": "If the account requires verification, a verification email will be sent.",
	})
}
