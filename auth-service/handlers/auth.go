package handlers

import (
	"auth-server/repository"
	"auth-server/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

func RegisterAuthRoutes(r *gin.Engine, db *gorm.DB, rdb0 *redis.Client, rdb1 *redis.Client, smtpConfig service.SmtpConfig) {
	repo := repository.NewUserRepo(db, rdb0, rdb1)

	svc, err := service.NewAuthService(repo, smtpConfig)
	if err != nil {
		panic(fmt.Errorf("failed initializing AuthService: %s", err))
	}

	r.POST("/auth/register", svc.RegisterHandler)
	r.POST("/auth/login", svc.LoginHandler)
	r.POST("/auth/token", svc.GetTokenHandler)
	r.POST("/auth/refresh", svc.RefreshTokenHandler)

	codeRequestGroup := r.Group("/", svc.JWTAuthMiddleware())
	codeRequestGroup.POST("/auth/register/code/request", svc.CodeRequestHandler)
	codeRequestGroup.POST("/auth/register/code/confirm", svc.CodeConfirmationHandler)
}
