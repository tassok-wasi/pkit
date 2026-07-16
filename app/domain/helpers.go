package domain

import (
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"fmt"

	"certman/app/utils"
)

// Helper to get KeyPair based on the type
func GetKey(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case RSA_2048:
		privKey, pubKey, err := utils.GetRSAKey(2048)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case RSA_4096:
		privKey, pubKey, err := utils.GetRSAKey(4096)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P224:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P224())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P256:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P256())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P384:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P384())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P521:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P521())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ED25519:
		privKey, pubKey, err := utils.GetED25519Key()
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// Helper to generate a Subject Key Identifier from a public key
func generateSKID(pubKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID using public key: %w", err)
	}
	// Classic RFC 5280 method 1: SHA-1 hash of the value of the BIT STRING subjectPublicKey
	hasher := sha1.New()
	hasher.Write(der)
	return hasher.Sum(nil), nil
}
