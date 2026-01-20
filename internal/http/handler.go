package http

import (
	"net/http"

	"auth-service/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Handler struct {
	auth *auth.Service
}

func NewHandler(auth *auth.Service) *Handler {
	return &Handler{auth: auth}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	token, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credential"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

func (h *Handler) Me(c *gin.Context) {
	claims := c.MustGet("user").(jwt.MapClaims)
	c.JSON(http.StatusOK, claims)
}
