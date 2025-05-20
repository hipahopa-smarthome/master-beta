package service

import (
	"ca-service/repository"
	"ca-service/utils"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

type CertService struct {
	CA                      *utils.CA
	ManufacturedDevicesRepo *repository.ManufacturedDevicesRepo
	ProvisioningPublicKey   *rsa.PublicKey
}

func NewCertService(database *gorm.DB, redisClient *redis.Client) (*CertService, error) {
	manufacturedDevicesRepo := repository.NewManufacturedDevicesRepo(database, redisClient)

	provisioningPublicKey, err := LoadPublicKey("keys/provisioning_public.pem")
	if err != nil {
		return nil, err
	}

	certPath := os.Getenv("CA_CERT_PATH")
	if certPath == "" {
		certPath = "certs/ca.crt"
	}
	keyPath := os.Getenv("CA_KEY_PATH")
	if keyPath == "" {
		keyPath = "certs/ca.key"
	}

	CA, err := utils.LoadCA(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA: %v", err)
	}
	return &CertService{
		CA:                      CA,
		ManufacturedDevicesRepo: manufacturedDevicesRepo,
		ProvisioningPublicKey:   provisioningPublicKey,
	}, nil
}

func (s *CertService) Ping(c *gin.Context) {
	c.JSON(200, "pong")
}

func (s *CertService) IssueDeviceCert(c *gin.Context) {
	type SignRequest struct {
		CSR        string `json:"csr" binding:"required"`
		MacAddress string `json:"mac_address" binding:"required"`
		Code       string `json:"code" binding:"required"`
	}

	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	macAddress, err := s.ManufacturedDevicesRepo.GetCertCode(req.Code)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusNotFound, gin.H{"error": "imvalid code"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot verify code"})
		log.Printf("cannot get code from redis: %v", err)
		return
	}

	if macAddress != req.MacAddress {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mac_address"})
		return
	}

	device, err := s.ManufacturedDevicesRepo.GetDeviceByMacAddress(req.MacAddress)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "such device wasn't manufactured"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot query database"})
		return
	}
	if device == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "such device wasn't found"})
		return
	}

	validDays := 365
	csr, err := utils.ParseCSR([]byte(req.CSR))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid csr"})
		return
	}

	caCert, err := utils.ParseCertificate(s.CA.PublicCert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot parse CA certificate"})
		log.Printf("cannot parse CA certificate: %v", err)
		return
	}

	caPrivateKey, err := utils.ParsePrivateKey(s.CA.PrivateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot parse CA private key"})
		log.Printf("cannot parse CA private key: %v", err)
		return
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, validDays),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caPrivateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create certificate"})
		log.Printf("cannot create certificate: %v", err)
		return
	}

	// Encode as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if certPEM == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode certificate to PEM"})
		log.Printf("failed to encode certificate to PEM: %v", err)
		return
	}

	err = s.ManufacturedDevicesRepo.DeleteCertCode(req.Code)
	if err != nil {
		log.Printf("cannot delete code from redis: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"certificate":    string(certPEM),
		"ca_certificate": string(s.CA.PublicCert),
		"valid_days":     validDays,
	})
}

func (s *CertService) VerifyToken(c *gin.Context) {
	type TokenRequest struct {
		Token string `json:"token" binding:"required"`
	}

	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	claims, err := s.ValidateToken(req.Token)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid token"})
		return
	}

	code, err := uuid.NewV7()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot generate code"})
		log.Printf("cannot generate code: %v", err)
		return
	}

	err = s.ManufacturedDevicesRepo.SetCertCode(code.String(), claims.MacAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot generate code"})
		log.Printf("cannot save code in redis: %v", err)
		return
	}

	c.JSON(200, gin.H{
		"code":       code.String(),
		"expires_in": 15 * time.Minute,
	})
}

func (s *CertService) RevokeCert(c *gin.Context) {

}

func (s *CertService) DownloadCrl(c *gin.Context) {

}

func (s *CertService) DownloadRoot(c *gin.Context) {

}
