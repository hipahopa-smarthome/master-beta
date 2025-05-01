package handlers

import (
	"auth-server/repository"
	"auth-server/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

func RegisterAuthRoutes(r *gin.Engine, db *gorm.DB, rdb *redis.Client) {
	repo := repository.NewUserRepo(db, rdb)

	svc, err := service.NewAuthService(repo)
	if err != nil {
		panic(fmt.Errorf("failed initializing AuthService: %s", err))
	}

	r.POST("/auth/register", svc.RegisterHandler)
	r.POST("/auth/login", svc.LoginHandler)
	r.POST("/auth/token", svc.GetTokenHandler)
	r.POST("/auth/refresh", svc.RefreshTokenHandler)
}
