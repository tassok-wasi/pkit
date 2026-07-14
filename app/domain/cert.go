package domain

import (
	"certman/app/utils"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GetBaseTemplate generates the basic certificate scaffolding.
func GetBaseTemplate(subject pkix.Name, serialNumber *big.Int, ttlInHour int, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ttlInHour) * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true, // Crucial for CA validation
	}
}

func GetCA(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair) (*x509.Certificate, error) {
	serialNumber := utils.GetSerialNumber()

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Self-signed CA: Subject Key ID and Authority Key ID match
	skid := generateSKID(keyPair.PublicKey)
	template.SubjectKeyId = skid
	template.AuthorityKeyId = skid

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error: cannot generate CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("error: cannot parse CA certificate: %w", err)
	}

	return caCert, nil
}

func GetIntermediate(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, errors.New("error: invalid parent certificate: parent must be a valid CA")
	}

	serialNumber := utils.GetSerialNumber()

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// MaxPathLen constraints
	template.MaxPathLen = 0
	template.MaxPathLenZero = true // This intermediate can only sign leaf certs, not more CAs

	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId = generateSKID(keyPair.PublicKey)
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	interBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error: cannot generate intermediate certificate: %w", err)
	}

	interCaCert, err := x509.ParseCertificate(interBytes)
	if err != nil {
		return nil, fmt.Errorf("error: cannot parse intermediate certificate: %w", err)
	}

	return interCaCert, nil
}

func GetLeaf(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, fmt.Errorf("error: invalid parent certificate: leaf must be signed by a CA/Intermediate")
	}

	serialNumber := utils.GetSerialNumber()

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, false)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId = generateSKID(keyPair.PublicKey)
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	leafBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error: cannot generate leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		return nil, fmt.Errorf("error: cannot parse leaf certificate: %w", err)
	}

	return leafCert, nil
}
