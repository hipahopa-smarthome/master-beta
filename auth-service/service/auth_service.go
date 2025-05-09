package service

import (
	"auth-server/models"
	"auth-server/repository"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"net/url"
	"time"
)

type AuthService struct {
	repo *repository.UserRepo

	smtpConfig SmtpConfig

	accessPrivateKey  *rsa.PrivateKey
	accessPublicKey   *rsa.PublicKey
	refreshPrivateKey *rsa.PrivateKey
	refreshPublicKey  *rsa.PublicKey

	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

type SmtpConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

func NewAuthService(r *repository.UserRepo, smtpConfig SmtpConfig) (*AuthService, error) {
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
		smtpConfig:           smtpConfig,
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
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "User with this email already exists",
		})
		return
	}
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			log.Printf("error while checking if user exists: %v", err)
			return
		}
	}

	user, err := s.repo.CreateUser(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		log.Printf("Failed to create user: %v\n", err)
		return
	}

	err = s.SendEmailConfirmationCode(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send email confirmation code",
		})
		log.Printf("Failed to send email confirmation code: %v\n", err)
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

	c.JSON(http.StatusCreated, gin.H{
		"user": gin.H{
			"id":        user.ID,
			"email":     user.Email,
			"name":      user.Name,
			"createdAt": user.CreatedAt,
			"updatedAt": user.UpdatedAt,
		},
		"tokens": gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
			"expiresAt":    int64(s.accessTokenDuration.Seconds()),
		},
	})
}

func (s *AuthService) SendEmailConfirmationCode(user *models.User) error {
	// generate code
	confirmationCode := fmt.Sprintf("%06d", int(rand.Float32()*1000000))
	expiresAt := 15 * time.Minute

	err := s.repo.SetEmailByConfirmationCode(confirmationCode, user.Email, expiresAt)
	if err != nil {
		return err
	}

	// send code
	emailBody := fmt.Sprintf(`
        <h1>Your Verification Code</h1>
        <p>Please use the following code to verify your email:</p>
        <h2 style="font-size: 24px; letter-spacing: 2px;">%s</h2>
        <p>This code will expire in %s minutes.</p>
    `, confirmationCode, fmt.Sprintf("%.0f", expiresAt.Minutes()))

	err = s.sendEmail([]string{user.Email}, "Your Verification Code", emailBody)
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (s *AuthService) sendEmail(to []string, subject, body string) error {
	auth := smtp.PlainAuth("", s.smtpConfig.Username, s.smtpConfig.Password, s.smtpConfig.Host)

	message := []byte(
		"Subject: " + subject + "\r\n" +
			"To: " + to[0] + "\r\n" +
			"From: " + s.smtpConfig.Username + "\r\n\r\n" +
			body + "\r\n",
	)

	err := smtp.SendMail(
		s.smtpConfig.Host+":"+s.smtpConfig.Port,
		auth,
		s.smtpConfig.Username,
		to,
		message,
	)

	return err
}

func (s *AuthService) CodeRequestHandler(c *gin.Context) {
	jwtUserEmail, exists := c.Get("userEmail")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user",
		})
		return
	}

	type CodeBody struct {
		Email string `json:"email"`
	}

	var body CodeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	if body.Email != jwtUserEmail {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(body.Email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "cannot query database",
			})
			log.Printf("error while checking if user exists: %v", err)
			return
		}
	}
	if user.Confirmed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user with this email is already confirmed",
		})
		return
	}

	err = s.SendEmailConfirmationCode(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to send email confirmation code",
		})
		log.Printf("Failed to send email confirmation code: %v\n", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "code sent",
	})
}

func (s *AuthService) CodeConfirmationHandler(c *gin.Context) {
	jwtUserEmail, exists := c.Get("userEmail")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user",
		})
		return
	}

	type CodeBody struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}

	var body CodeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	if body.Email != jwtUserEmail {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(body.Email)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "cannot query database",
			})
			log.Printf("error while checking if user exists: %v", err)
			return
		}
	}
	if user.Confirmed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user with this email is already confirmed",
		})
		return
	}

	correct, err := s.repo.CheckConfirmationCode(body.Code, body.Email)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "code is incorrect",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot check code",
		})
		log.Printf("error while checking code: %v", err)
		return
	}

	if !correct {
		c.JSON(http.StatusNotAcceptable, gin.H{
			"error": "code is incorrect",
		})
		return
	}

	err = s.repo.SetUserStatusConfirmed(body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to set user status confirmed",
		})
		log.Printf("Failed to set user status confirmed: %v\n", err)
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
		"email":         body.Email,
		"confirmed":     true,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int64(s.accessTokenDuration.Seconds()),
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
	if c.ContentType() != "application/x-www-form-urlencoded" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "unsupported_media_type"})
		return
	}

	grantType := c.PostForm("grant_type")
	if grantType != "refresh_token" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Missing refresh_token"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.refreshPublicKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid or expired refresh token",
		})
		return
	}

	user, err := s.repo.GetUserById(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_grant",
			"error_description": "User not found",
		})
		return
	}

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	refreshTokenNew, err := s.generateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(s.accessTokenDuration.Seconds()),
		"refresh_token": refreshTokenNew,
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

	if s.repo.DeleteLoginDataByCode(req.Code) != nil {
		log.Printf("Failed to delete login data: %v\n", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int64(s.accessTokenDuration.Seconds()),
	})
}
