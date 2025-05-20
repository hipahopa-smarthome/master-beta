package utils

import (
	"fmt"
	"os"
)

type CA struct {
	PrivateKey []byte
	PublicCert []byte
}

func LoadCA(certPath, keyPath string) (*CA, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	return &CA{
		PrivateKey: keyBytes,
		PublicCert: certBytes,
	}, nil
}
