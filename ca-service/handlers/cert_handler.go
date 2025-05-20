package handlers

import (
	"ca-service/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

func RegisterCertsRoutes(r *gin.Engine, db *gorm.DB, redisClient *redis.Client) error {
	svc, err := service.NewCertService(db, redisClient)
	if err != nil {
		return fmt.Errorf("cannot create cert service %v", err)
	}

	r.POST("/ping", svc.Ping)

	r.POST("/provisioning/sign-certificate", svc.IssueDeviceCert)
	r.POST("/provisioning/verify-token", svc.VerifyToken)
	r.POST("/provisioning/revoke", svc.RevokeCert)
	r.POST("/ca/certificates/crl", svc.DownloadCrl)
	r.POST("/ca/certificates/root", svc.DownloadRoot)

	return nil
}
