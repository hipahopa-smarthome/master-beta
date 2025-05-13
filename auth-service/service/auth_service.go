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
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
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

	// validate email
	_, err := mail.ParseAddress(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email address",
		})
		return
	}
	// validate password
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 8 characters",
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

	err = s.sendEmailConfirmationCode(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to send email confirmation code",
		})
		log.Printf("failed to send email confirmation code: %v\n", err)
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

	//c.JSON(http.StatusCreated, models.LoginResponse{
	//	AccessToken:  accessToken,
	//	RefreshToken: refreshToken,
	//	TokenType:    "Bearer",
	//	Email:        "",
	//	Confirmed:    false,
	//	ExpiresIn:    0,
	//})
	c.SetCookie("access_token",
		accessToken,
		int(s.accessTokenDuration.Seconds()),
		"/",
		"",
		true,
		true)

	c.SetCookie(
		"refresh_token",
		refreshToken,
		int(s.refreshTokenDuration.Seconds()),
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"email":     user.Email,
		"confirmed": user.Confirmed,
	})
}

func (s *AuthService) CodeRequestHandler(c *gin.Context) {
	jwtUserEmail, exists := c.Get("userEmail")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid user",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(fmt.Sprint(jwtUserEmail))
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

	err = s.sendEmailConfirmationCode(user)
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
		Code string `json:"code"`
	}

	var body CodeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(fmt.Sprint(jwtUserEmail))
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

	correct, err := s.repo.CheckCodeWithEmail(body.Code, fmt.Sprint(jwtUserEmail))
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

	err = s.repo.SetUserStatusConfirmed(fmt.Sprint(jwtUserEmail))
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

	c.JSON(http.StatusOK, models.LoginResponse{
		TokenType:    "Bearer",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Email:        user.Email,
		Confirmed:    user.Confirmed,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
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

	// this part is for yandex-smarthome auth (https://yandex.ru/dev/dialogs/smart-home/doc/ru/auth/how-it-works)
	if c.Query("smart-home") == "true" {
		code := uuid.New().String()
		clientId := c.Query("client_id")
		userId := user.ID
		state := c.Query("state")
		scope := c.Query("scope")

		err := s.repo.SetLoginDataByCode(code, clientId, userId, state, scope)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to set login data",
			})
			log.Printf("failed to set login data: %v\n", err)
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

	c.SetCookie("access_token",
		accessToken,
		int(s.accessTokenDuration.Seconds()),
		"/",
		"",
		true,
		true)

	c.SetCookie(
		"refresh_token",
		refreshToken,
		int(s.refreshTokenDuration.Seconds()),
		"/",
		"",
		true,
		true,
	)

	//c.JSON(http.StatusOK, models.LoginResponse{
	//	TokenType:    "Bearer",
	//	AccessToken:  accessToken,
	//	RefreshToken: refreshToken,
	//	Email:        user.Email,
	//	Confirmed:    user.Confirmed,
	//	Name:         user.Name,
	//	ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
	//})
	c.JSON(http.StatusOK, gin.H{
		"email":     user.Email,
		"confirmed": user.Confirmed,
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

	yandexQuery := c.Query("yandex-smart-home")
	isYandexRequest := yandexQuery != ""

	if isYandexRequest {
		c.JSON(http.StatusOK, models.LoginResponse{
			TokenType:    "Bearer",
			AccessToken:  accessToken,
			RefreshToken: refreshTokenNew,
			ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
		})
	} else {
		c.SetCookie(
			"access_token",
			accessToken,
			int(s.accessTokenDuration.Seconds()),
			"/",
			"",
			true,
			true,
		)

		c.SetCookie(
			"refresh_token",
			refreshTokenNew,
			int(s.refreshTokenDuration.Seconds()),
			"/",
			"",
			true,
			true,
		)

		c.JSON(http.StatusOK, gin.H{
			"email":     user.Email,
			"confirmed": user.Confirmed,
		})
	}
}

// GetTokenHandler is for yandex-smarthome auth (https://yandex.ru/dev/dialogs/smart-home/doc/ru/auth/how-it-works)
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
		log.Printf("Failed to retrieve login data: %v\n", err)
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
		"token_type":    "Bearer",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    s.accessTokenDuration.Seconds(),
	})
}

func (s *AuthService) ResetPasswordHandler(c *gin.Context) {
	type ResetPasswordRequest struct {
		Email string `json:"email" binding:"required"`
	}

	var req ResetPasswordRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User with this email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to get user from db: %v\n", err)
		return
	}

	// generate uuidV7Code code for resetting password
	uuidV7Code, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to generate uuidV7Code: %v\n", err)
		return
	}

	uuidCode := uuidV7Code.String()

	err = s.repo.SetResetPasswordCode(uuidCode, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to save code in redis: %v\n", err)
		return
	}

	err = s.sendResetPasswordCode(uuidCode, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to send link on email: %v\n", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"email": user.Email,
	})
}

func (s *AuthService) ResetChangePasswordHandler(c *gin.Context) {
	type ConfirmResetPasswordRequest struct {
		Code        string `json:"code"`
		NewPassword string `json:"password" binding:"required"`
	}
	var req ConfirmResetPasswordRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	// check if code is valid (present in redis)
	emailInDb, err := s.repo.GetEmailByResetPasswordCode(req.Code)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Reset password code not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to get email by reset password code: %v\n", err)
		return
	}

	user, err := s.repo.GetUserByEmail(emailInDb)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User with this email not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to get user from db: %v\n", err)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to hash password: %v\n", err)
		return
	}

	user.Password = string(hashedPassword)
	err = s.repo.UpdateUserPassword(user.ID, user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "cannot reset password",
		})
		log.Printf("failed to update user in db: %v\n", err)
		return
	}

	err = s.repo.DeleteResetPasswordCode(req.Code)
	if err != nil {
		log.Printf("failed to delete reset password code: %v\n", err)
	}
	c.JSON(http.StatusOK, gin.H{})
}

func (s *AuthService) sendResetPasswordCode(code string, email string) error {
	emailBody := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
	<meta charset="UTF-8">
	<title>Password Reset</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			background-color: #f4f4f4;
			padding: 20px;
		}
	.container {
		max-width: 600px;
		margin: auto;
		background: white;
		padding: 30px;
		border-radius: 8px;
		box-shadow: 0 0 10px rgba(0,0,0,0.1);
	}
	h1 {
		color: #333;
	}
	p {
		font-size: 16px;
		line-height: 1.5;
	}
	.button {
		display: inline-block;
		margin-top: 20px;
		padding: 12px 24px;
		background-color: #335f8f;
		color: white;
		text-decoration: none;
		font-weight: bold;
		border-radius: 5px;
	}
	a {
      color: white;
    }
	.footer {
		margin-top: 30px;
		font-size: 14px;
		color: #777;
	}
	</style>
	</head>
	<body>
	<div class="container">
	<h1>Password Reset Request</h1>
	<p>We received a request to reset your account password. If this was you, please click the button below to continue:</p>

	<a href="https://smarthome.hipahopa.ru/reset-password?code=%s&email=%s" class="button">Reset Password</a>

	<p>If you did not request a password reset, you can safely ignore this email.</p>

	<div class="footer">
		This link will expire in 15 minutes for security reasons.
	</div>
	</div>
	</body>
	</html>`, code, email)

	err := s.sendEmail([]string{email}, "Password Reset Request", emailBody)
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}

func (s *AuthService) sendEmailConfirmationCode(user *models.User) error {
	// generate code
	confirmationCode := fmt.Sprintf("%06d", int(rand.Float32()*1000000))
	expiresAt := 15 * time.Minute

	err := s.repo.SetEmailConfirmationCode(confirmationCode, user.Email, expiresAt)
	if err != nil {
		return err
	}

	// send code
	emailBody := fmt.Sprintf(`
       <!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<title>Verification Code</title>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #f9f9f9;
					padding: 20px;
				}
				.email-container {
					max-width: 500px;
					margin: auto;
					background-color: #ffffff;
					padding: 30px;
					border-radius: 8px;
					box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
				}
				h2 {
					color: #333333;
					font-size: 24px;
					margin-bottom: 20px;
				}
				p {
					font-size: 16px;
					color: #555555;
					line-height: 1.5;
				}
				.code {
					display: inline-block;
					margin: 20px 0;
					padding: 12px 24px;
					font-size: 22px;
					letter-spacing: 2px;
					font-weight: bold;
					color: #333333;
					background-color: #f0f0f0;
					border-radius: 6px;
					word-break: break-all;
				}
				.footer {
					margin-top: 20px;
					font-size: 14px;
					color: #aaaaaa;
				}
			</style>
		</head>
		<body>
			<div class="email-container">
				<h2>Your Verification Code</h2>
				<p>Please use the following code to verify your email:</p>
				<div class="code">%s</div>
				<p>This code will expire in %s minutes.</p>
				<div class="footer">
					If you did not request this code, please ignore this email.
				</div>
			</div>
		</body>
		</html>
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
		"From: " + subject + "\r\n" +
			"To: " + strings.Join(to, ", ") + "\r\n" +
			"From: " + "Smarthome" + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"\r\n" + // Empty line to separate headers from body
			body,
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
