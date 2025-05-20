package service

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

type Claims struct {
	MacAddress   string `json:"mac_address"`
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	jwt.RegisteredClaims
}

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM(keyData)
}

func (s *CertService) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.ProvisioningPublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token is expired")
	}

	return claims, nil
}
