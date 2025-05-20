package service

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"time"
)

func (s *ProvisioningService) GenerateProvisioningToken(c *gin.Context) {
	type ManufacturingRequest struct {
		MacAddress   string `json:"mac_address"`
		SerialNumber string `json:"serial_number"`
		Model        string `json:"model"`
	}

	var req ManufacturingRequest
	if err := c.BindJSON(&req); err != nil {
		err = fmt.Errorf("cannot bind json: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Println(err.Error())
		return
	}

	claims := Claims{
		MacAddress:   req.MacAddress,
		SerialNumber: req.SerialNumber,
		Model:        req.Model,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "provisioning-service",
		},
	}

	token, err := s.GenerateToken(&claims)
	if err != nil {
		err = fmt.Errorf("cannot generate token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}
