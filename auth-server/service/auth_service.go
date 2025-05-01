package service

import (
	"auth-server/models"
	"auth-server/repository"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"time"
)

type AuthService struct {
	repo *repository.UserRepo

	accessPrivateKey  *rsa.PrivateKey
	accessPublicKey   *rsa.PublicKey
	refreshPrivateKey *rsa.PrivateKey
	refreshPublicKey  *rsa.PublicKey

	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

func NewAuthService(r *repository.UserRepo) (*AuthService, error) {
	accessPrivateKey, err := loadPrivateKey("keys/access_private.pem")
	if err != nil {
		return nil, err
	}

	accessPublicKey, err := loadPublicKey("keys/access_public.pem")
	if err != nil {
		return nil, err
	}

	refreshPrivateKey, err := loadPrivateKey("keys/refresh_private.pem")
	if err != nil {
		return nil, err
	}

	refreshPublicKey, err := loadPublicKey("keys/refresh_public.pem")
	if err != nil {
		return nil, err
	}

	return &AuthService{
		repo:                 r,
		accessPrivateKey:     accessPrivateKey,
		accessPublicKey:      accessPublicKey,
		refreshPrivateKey:    refreshPrivateKey,
		refreshPublicKey:     refreshPublicKey,
		accessTokenDuration:  15 * time.Minute,
		refreshTokenDuration: 7 * 24 * time.Hour,
	}, nil
}

func (s *AuthService) RegisterHandler(c *gin.Context) {
	var req models.RegistrationUser

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	existingUser, err := s.repo.GetUserByEmail(req.Email)
	if err == nil && existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this email already exists",
		})
		return
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User with this email does not exist",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	user, err := s.repo.CreateUser(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		log.Printf("Failed to create user: %v\n", err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":        user.ID,
		"email":     user.Email,
		"name":      user.Name,
		"createdAt": user.CreatedAt,
		"updatedAt": user.UpdatedAt,
	})
}

func (s *AuthService) LoginHandler(c *gin.Context) {
	var req models.LoginUser

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		log.Printf("Failed to generate access token: %v\n", err)
		return
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate refresh token",
		})
		log.Printf("Failed to generate refresh token: %v\n", err)
		return
	}

	if c.Query("smart-home") == "true" {
		code := uuid.New().String()
		clientId := c.Query("client_id")
		userId := user.ID
		state := c.Query("state")
		scope := c.Query("scope")

		err := s.repo.SetLoginDataByCode(code, clientId, userId, state, scope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set login data",
			})
			return
		}

		redirectURL := fmt.Sprintf(
			"https://social.yandex.net/broker/redirect?code=%s&client_id=%s&state=%s&scope=%s",
			url.QueryEscape(code),
			url.QueryEscape(clientId),
			url.QueryEscape(state),
			url.QueryEscape(scope),
		)

		// Return the redirect URL in the response
		c.JSON(http.StatusOK, gin.H{
			"redirect_url": redirectURL,
		})
		return
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Email:        user.Email,
		Name:         user.Name,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
	})
}

func (s *AuthService) RefreshTokenHandler(c *gin.Context) {
	var req models.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.refreshPublicKey, nil
		},
	)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired refresh token",
		})
		return
	}

	user, err := s.repo.GetUserById(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not found",
		})
		return
	}

	newAccessToken, err := s.generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		return
	}

	newRefreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    int64(s.accessTokenDuration.Seconds()),
	})
}

func (s *AuthService) GetTokenHandler(c *gin.Context) {
	var req models.TokenRequest

	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	loginData, err := s.repo.GetLoginDataByCode(req.Code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve login data",
		})
		return
	}

	if loginData == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Login data not found",
		})
		return
	}

	if loginData.ClientID != req.ClientID {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Login data not found",
		})
		return
	}

	user, err := s.repo.GetUserById(loginData.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not found",
		})
		return
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate access token",
		})
		log.Printf("Failed to generate access token: %v\n", err)
		return
	}
	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate refresh token",
		})
		log.Printf("Failed to generate refresh token: %v\n", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int64(s.accessTokenDuration.Seconds()),
	})
}
