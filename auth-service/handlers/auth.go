package handlers

import (
	"auth-server/db"
	"auth-server/repository"
	"auth-server/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RegisterAuthRoutes(r *gin.Engine, db *gorm.DB, redisClients *db.RedisClients, smtpConfig service.SmtpConfig) {
	repo := repository.NewUserRepo(db, redisClients)

	svc, err := service.NewAuthService(repo, smtpConfig)
	if err != nil {
		panic(fmt.Errorf("failed initializing AuthService: %s", err))
	}

	r.POST("/auth/register", svc.RegisterHandler)
	r.POST("/auth/login", svc.LoginHandler)
	r.POST("/auth/token", svc.GetTokenHandler)
	r.POST("/auth/refresh", svc.RefreshTokenHandler)

	r.POST("/auth/reset-password", svc.ResetPasswordHandler)
	r.POST("/auth/change-password", svc.ChangePasswordHandler)

	codeRequestGroup := r.Group("/", svc.JWTAuthMiddleware())
	codeRequestGroup.POST("/auth/register/code/request", svc.CodeRequestHandler)
	codeRequestGroup.POST("/auth/register/code/confirm", svc.CodeConfirmationHandler)
}
