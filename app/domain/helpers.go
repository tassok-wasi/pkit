package domain

import (
	"crypto/sha1"
	"crypto/x509"
)

// Helper to generate a Subject Key Identifier from a public key
func generateSKID(pubKey any) []byte {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil
	}
	// Classic RFC 5280 method 1: SHA-1 hash of the value of the BIT STRING subjectPublicKey
	hasher := sha1.New()
	hasher.Write(der)
	return hasher.Sum(nil)
}
