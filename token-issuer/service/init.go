package service

import (
	"crypto/rsa"
	"github.com/gin-gonic/gin"
	"net/http"
)

type ProvisioningService struct {
	provisioningPrivateKey *rsa.PrivateKey
	provisioningPublicKey  *rsa.PublicKey
}

func NewProvisioningService() (*ProvisioningService, error) {
	provisioningPrivateKey, err := LoadPrivateKey("keys/provisioning_private.pem")
	if err != nil {
		return nil, err
	}

	provisioningPublicKey, err := LoadPublicKey("keys/provisioning_public.pem")
	if err != nil {
		return nil, err
	}

	return &ProvisioningService{
		provisioningPrivateKey: provisioningPrivateKey,
		provisioningPublicKey:  provisioningPublicKey,
	}, nil
}

func (s *ProvisioningService) Ping(c *gin.Context) {
	c.JSON(http.StatusOK, "pong")
}
