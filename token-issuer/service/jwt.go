package service

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

type Claims struct {
	MacAddress   string `json:"mac_address"`
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	jwt.RegisteredClaims
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(keyData)
}

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM(keyData)
}

func (s *ProvisioningService) GenerateToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.provisioningPrivateKey)
}
