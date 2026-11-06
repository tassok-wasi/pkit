// Copyright 2026 Tassok Imam Wasi

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pki

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
)

// CertType defines the role of the certificate in the PKI hierarchy.
type CertType string

const (
	TypeRootCA       CertType = "CA"
	TypeIntermediate CertType = "INTERMEDIATE"
	TypeLeaf         CertType = "LEAF"
)

// CertOptions holds parameters for generating Root CAs, Intermediates, or Leaf certificates.
type CertOptions struct {
	Type       CertType
	Subject    pkix.Name
	SANs       SANs
	TTLInHours int
	KeyPair    *KeyPair          // Target cert key pair
	ParentCert *x509.Certificate // Issuer cert (nil if self-signed Root CA)
	ParentKey  any               // Issuer private key (nil if self-signed Root CA)
	Usages     *KeyUsageConfig   // Custom key usages (optional)

	// PathLen controls intermediate CA path constraints.
	// - Use a pointer (*int) so nil means "no constraint specified".
	// - Pass a pointer to 0 for MaxPathLen = 0 (leaf signing only).
	// - Pass a pointer to >0 for nested intermediate depth limits.
	PathLen *int
}

// IssueCertificate is the unified builder for generating any X.509 certificate tier.
func IssueCertificate(opts CertOptions) (*x509.Certificate, error) {
	if opts.KeyPair == nil || opts.KeyPair.PublicKey == nil {
		return nil, errors.New("target keypair with public key is required")
	}
	if opts.TTLInHours <= 0 {
		return nil, errors.New("certificate TTL must be greater than zero")
	}
	switch opts.Type {
	case TypeRootCA, TypeIntermediate, TypeLeaf:
	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", opts.Type)
	}

	serialNumber, err := crypto.GetSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	isCA := opts.Type == TypeRootCA || opts.Type == TypeIntermediate
	notBefore := time.Now().UTC()
	template := GetBaseTemplate(opts.Subject, serialNumber, opts.TTLInHours, isCA)
	template.NotBefore = notBefore
	template.NotAfter = notBefore.Add(time.Duration(opts.TTLInHours) * time.Hour)

	if opts.Type != TypeRootCA {
		template.DNSNames = opts.SANs.DNSNames
		template.EmailAddresses = opts.SANs.EmailAddresses
		template.IPAddresses = opts.SANs.IPAddresses
		template.URIs = opts.SANs.URIs
	}

	if opts.Type == TypeIntermediate && opts.PathLen != nil {
		if *opts.PathLen < 0 {
			return nil, errors.New("path length must not be negative")
		}
		if *opts.PathLen == 0 {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		} else {
			template.MaxPathLen = *opts.PathLen
			template.MaxPathLenZero = false
		}
	}

	if err := applyKeyUsages(template, opts); err != nil {
		return nil, err
	}

	skid, err := GenerateSKID(opts.KeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID: %w", err)
	}
	template.SubjectKeyId = skid

	var signingCert *x509.Certificate
	var signingKey any

	if opts.Type == TypeRootCA {
		template.AuthorityKeyId = skid
		signingCert = template
		signingKey = opts.KeyPair.PrivateKey
		if signingKey == nil {
			return nil, errors.New("private key is required for a self-signed root CA")
		}
	} else {
		if opts.ParentCert == nil || opts.ParentKey == nil {
			return nil, fmt.Errorf("parent certificate and private key required for type: %s", opts.Type)
		}
		if !opts.ParentCert.IsCA {
			return nil, errors.New("parent certificate must be a CA")
		}
		if opts.ParentCert.KeyUsage != 0 && opts.ParentCert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("parent certificate is not permitted to sign certificates")
		}

		now := time.Now()
		if now.Before(opts.ParentCert.NotBefore) {
			return nil, errors.New("parent certificate is not valid yet")
		}
		if now.After(opts.ParentCert.NotAfter) {
			return nil, errors.New("parent certificate has expired")
		}
		if isCA && opts.ParentCert.MaxPathLenZero {
			return nil, errors.New("parent certificate path length does not allow another CA")
		}
		if template.NotAfter.After(opts.ParentCert.NotAfter) {
			return nil, fmt.Errorf("certificate validity exceeds issuer expiry (%s)", opts.ParentCert.NotAfter.Format(time.RFC3339))
		}

		signer, ok := opts.ParentKey.(stdcrypto.Signer)
		if !ok {
			return nil, errors.New("parent private key does not implement crypto.Signer")
		}
		if !samePublicKey(signer.Public(), opts.ParentCert.PublicKey) {
			return nil, errors.New("parent private key does not match parent certificate")
		}

		template.AuthorityKeyId = opts.ParentCert.SubjectKeyId
		signingCert = opts.ParentCert
		signingKey = opts.ParentKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, signingCert, opts.KeyPair.PublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, nil
}

// samePublicKey compares two public keys by their PKIX encoding.
func samePublicKey(a, b any) bool {
	derA, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	derB, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(derA, derB)
}

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

// Internal helper to apply key usages dynamically or fall back to standard defaults.
func applyKeyUsages(template *x509.Certificate, opts CertOptions) error {
	if opts.Usages != nil && len(opts.Usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range opts.Usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else if template.IsCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		if _, ok := opts.KeyPair.PublicKey.(*rsa.PublicKey); ok {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
	}

	if template.IsCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else if template.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return errors.New("leaf certificates cannot have cert-sign or crl-sign key usage")
	}

	if opts.Usages != nil && len(opts.Usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = opts.Usages.ExtKeyUsages
	} else if opts.Type == TypeLeaf {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	return nil
}
