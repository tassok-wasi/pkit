package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func EncodeToPem(bytes []byte, blockType string) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})

	if pemBytes == nil {
		return "", errors.New("cannot encode to pem")
	}

	return string(pemBytes), nil
}

func DecodeToPem(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return block.Bytes, nil
}

func ReturnPrivPubPem(privateKey any, publicKey any) (string, string, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	masterKey, err := GetMasterKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get master key from os keyring: %w", err)
	}
	privBytesBlob, err := Encrypt(privBytes, masterKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	privBlobPem, err := EncodeToPem(privBytesBlob, "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return "", "", err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPem, err := EncodeToPem(pubBytes, "PUBLIC KEY")
	if err != nil {
		return "", "", err
	}

	return privBlobPem, pubPem, nil
}

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	certBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parse Certificate: %w", err)
	}
	return cert, nil
}

func DecryptPrivKey(privPem []byte) ([]byte, error) {
	privKey, err := DecodeToPem(privPem)
	if err != nil {
		return nil, err
	}

	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, err
	}

	decryptedPrivKey, err := Decrypt(privKey, masterKey)
	if err != nil {
		return nil, err
	}

	return decryptedPrivKey, nil
}

func ParseKeys(privPem []byte, pubPem []byte) (any, any, error) {
	decryptedPrivKey, err := DecryptPrivKey(privPem)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := DecodeToPem(pubPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return privateKey, publicKey, nil
}

func GetKeyDetails(key any) (algoType string, sizeInfo string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		algoType = "RSA Private Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PrivateKey:
		algoType = "ECDSA Private Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PrivateKey:
		algoType = "Ed25519 Private Key"
		sizeInfo = "256-bit seed"
	case *rsa.PublicKey:
		algoType = "RSA Public Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PublicKey:
		algoType = "ECDSA Public Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PublicKey:
		algoType = "Ed25519 Public Key"
		sizeInfo = "256-bit"
	default:
		algoType = fmt.Sprintf("Unknown (%T)", key)
		sizeInfo = "N/A"
	}
	return algoType, sizeInfo
}

func TruncateHex(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	fullHex := hex.EncodeToString(b)
	if len(fullHex) > 32 {
		return fullHex[:32]
	}
	return fullHex
}

// Formats a byte slice fingerprint into standard double-spaced format (e.g., "AA:BB:CC:...")
func FormatFingerprint(b []byte) string {
	var parts []string
	for _, val := range b {
		parts = append(parts, fmt.Sprintf("%02X", val))
	}
	return strings.Join(parts, ":")
}
