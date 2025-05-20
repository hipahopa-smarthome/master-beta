package handlers

import (
	"crypto/rsa"
	"fmt"
	"github.com/gin-gonic/gin"
	"token-issuer/service"
)

type Config struct {
	provisioningPrivateKey *rsa.PrivateKey
	provisioningPublicKey  *rsa.PublicKey
}

func RegisterRoutes(r *gin.Engine) {
	svc, err := service.NewProvisioningService()
	if err != nil {
		panic(fmt.Sprintf("rrror creating provisioning service: %v", err))
	}

	r.POST("/ping", svc.Ping)

	// this endpoint is used for generating token that will be used by
	// device to authenticate on cert request
	// must be private (e.g. inside factory)
	r.POST("/provisioning/token", svc.GenerateProvisioningToken)
}
