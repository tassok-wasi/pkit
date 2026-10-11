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

// Package service is the application layer of pkit. It owns all database
// access and domain orchestration so that the CLI layer can stay thin: the
// commands only translate flags into requests and render results.
package service

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

// Service coordinates persistence and PKI domain logic for the CLI.
type Service struct {
	db *sql.DB
	q  sqlc.Querier
}

// New constructs a Service bound to a database handle and its querier.
func New(db *sql.DB, q sqlc.Querier) *Service {
	return &Service{db: db, q: q}
}

// getCertificateRecord fetches a certificate row by ID.
func (s *Service) getCertificateRecord(ctx context.Context, id int64) (sqlc.Certificate, error) {
	return s.q.GetCertificateByID(ctx, id)
}

// parseCertificateRecord parses the PEM payload of a stored certificate.
func parseCertificateRecord(rec sqlc.Certificate) (*x509.Certificate, error) {
	return crypto.ParseCertificate([]byte(rec.CertificatePem))
}

// parseKeyRecord decrypts and parses the key pair stored in a key row.
func parseKeyRecord(rec sqlc.Key) (privateKey any, publicKey any, err error) {
	return crypto.ParseKeys([]byte(rec.PrivateKeyPem), []byte(rec.PublicKeyPem))
}

// resolveIssuer loads and validates the issuing certificate and its private key.
// It returns the parsed issuer certificate, the issuer private key, and the
// issuer's serial number for storage on the issued certificate.
func (s *Service) resolveIssuer(ctx context.Context, issuerID int64) (*x509.Certificate, any, string, error) {
	issuerDBCert, err := s.q.GetCertificateByID(ctx, issuerID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to fetch issuer Certificate from DB: %w", err)
	}

	issuerCert, err := parseCertificateRecord(issuerDBCert)
	if err != nil {
		return nil, nil, "", err
	}
	if issuerDBCert.IsRevoked.Valid && issuerDBCert.IsRevoked.Int64 == 1 {
		return nil, nil, "", fmt.Errorf("issuer certificate is revoked")
	}
	if !issuerCert.IsCA {
		return nil, nil, "", fmt.Errorf("issuer certificate is not a CA")
	}

	issuerKeys, err := s.q.GetKeyByID(ctx, issuerDBCert.KeyID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to fetch issuer key from DB: %w", err)
	}
	issuerPrivateKey, _, err := parseKeyRecord(issuerKeys)
	if err != nil {
		return nil, nil, "", err
	}

	return issuerCert, issuerPrivateKey, issuerDBCert.SerialNumber, nil
}

// storeCertificate persists a freshly issued certificate and returns the row.
func (s *Service) storeCertificate(ctx context.Context, q sqlc.Querier, cert *x509.Certificate, certType pki.CertType, keyID int64, issuerSerial string) (sqlc.Certificate, error) {
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	skidHex := hex.EncodeToString(cert.SubjectKeyId)
	akidHex := hex.EncodeToString(cert.AuthorityKeyId)
	if akidHex == "" {
		// Fallback for self-signed root anchors.
		akidHex = skidHex
	}

	return q.CreateCertificate(ctx, sqlc.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", cert.SerialNumber),
		CommonName:         cert.Subject.CommonName,
		Type:               string(certType),
		KeyID:              keyID,
		IssuerSerialNumber: sql.NullString{String: issuerSerial, Valid: issuerSerial != ""},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		IsRevoked:          sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		CertificatePem:     string(certPem),
	})
}

// buildChain walks the AKID -> SKID pointers upward from the given certificate
// and returns the ordered list of parent certificates (excluding the leaf).
func (s *Service) buildChain(ctx context.Context, current *x509.Certificate) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	workingCert := current
	const maxChainDepth = 10
	for depth := 0; depth < maxChainDepth; depth++ {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			if depth == 0 {
				return nil, fmt.Errorf("failed to build chain. Provided Certificate itself a Root CA Certificate")
			}
			break
		}

		if len(workingCert.AuthorityKeyId) == 0 {
			return nil, fmt.Errorf("failed to build chain. Chain ended early: %s lacks AKID", workingCert.Subject.CommonName)
		}
		if workingCert.Subject.String() != "" && workingCert.Issuer.String() != "" && workingCert.Subject.String() != workingCert.Issuer.String() && len(workingCert.AuthorityKeyId) == len(workingCert.SubjectKeyId) && string(workingCert.AuthorityKeyId) == string(workingCert.SubjectKeyId) {
			return nil, fmt.Errorf("failed to build chain. Chain ended early: %s has self-referential AKID but is not self-issued", workingCert.Subject.CommonName)
		}

		akidHex := hex.EncodeToString(workingCert.AuthorityKeyId)
		parentDBCert, err := s.q.GetCertificateBySKID(ctx, akidHex)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Certificate from DB: %w", err)
		}
		if parentDBCert.CommonName != "" && workingCert.Issuer.CommonName != "" && parentDBCert.CommonName != workingCert.Issuer.CommonName {
			return nil, fmt.Errorf("failed to build chain. Chain ended early: issuer mismatch for %s", workingCert.Subject.CommonName)
		}
		parentCert, err := parseCertificateRecord(parentDBCert)
		if err != nil {
			return nil, err
		}
		if workingCert.Issuer.String() != "" && parentCert.Subject.String() != workingCert.Issuer.String() {
			return nil, fmt.Errorf("failed to build chain. Chain ended early: issuer mismatch for %s", workingCert.Subject.CommonName)
		}

		chain = append(chain, parentCert)
		workingCert = parentCert
	}

	return chain, nil
}
