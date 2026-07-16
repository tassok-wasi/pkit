package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadFile(filePath string) ([]byte, error) {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return nil, err
	}

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file data: %w", err)
	}

	return fileBytes, nil
}

// ReadCert reads file and returns the x509.Certificate formatted cert
// filePath can be linux path, relative path, absolute path or just file name
func ReadCert(filePath string) (*x509.Certificate, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cert: %v", err)
	}

	return cert, nil
}

// ReadKey reads file and returns the pkcs#8 for private key and pkix for public key
// filePath can be linux path, relative path, absolute path or just file name
func ReadKey(filePath string) (any, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file does not contains valid key")
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	key, err := ReturnKey(fileBytes, block.Type)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func ReturnKeyWithBlockType(filePath string) (any, string, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("file does not contains valid key")
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, "", fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	key, err := ReturnKey(fileBytes, block.Type)
	if err != nil {
		return nil, "", err
	}

	return key, block.Type, nil
}

func ReturnKey(bytes []byte, blockType string) (any, error) {
	switch blockType {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		return pub, nil
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return priv, nil
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
		return priv, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
		}
		return pub, nil
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key")
	}
}
