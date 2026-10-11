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

package service

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	store "github.com/tassok-wasi/pkit/internal/store"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"

	"software.sslmate.com/src/go-pkcs12"
)

// IssueRequest describes a certificate to issue at any tier of the hierarchy.
type IssueRequest struct {
	Type         pki.CertType
	Subject      pkix.Name
	SANs         pki.SANs
	TTL          string
	KeyID        int64
	IssuerID     int64
	KeyUsages    []string
	ExtKeyUsages []string
	PathLen      *int
}

// RotateRequest describes a certificate rotation.
type RotateRequest struct {
	ID       int64
	IssuerID int64
	KeyID    int64
}

// ListCertificatesRequest filters and paginates a certificate listing.
type ListCertificatesRequest struct {
	Limit  int
	Offset int
	Status string
	Type   string
}

// CertificateSummary is a normalized row for listing certificates.
type CertificateSummary struct {
	ID           int64
	SerialNumber string
	CommonName   string
	Type         string
	Status       string
	CreatedAt    time.Time
}

// DiffResult carries the two compared names and their structural differences.
type DiffResult struct {
	Name1 string
	Name2 string
	Diffs []pki.FieldDiff
}

// ExportRequest describes a single-artifact export to disk.
type ExportRequest struct {
	ID     int64
	Path   string
	Format string
}

// ExportBundleRequest describes a certificate + key bundle export.
type ExportBundleRequest struct {
	ID         int64
	Path       string
	Format     string
	PassPhrase string
}

// IssueCertificate issues a Root CA, Intermediate CA, or Leaf certificate and
// persists it.
func (s *Service) IssueCertificate(ctx context.Context, req IssueRequest) (sqlc.Certificate, error) {
	hours, err := crypto.ParseTTLToHours(req.TTL)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := s.q.GetKeyByID(ctx, req.KeyID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to get Key from DB: %w", err)
	}
	privateKey, publicKey, err := parseKeyRecord(dbKey)
	if err != nil {
		return sqlc.Certificate{}, err
	}

	var parentCert *x509.Certificate
	var parentKey any
	var issuerSerial string

	if req.Type != pki.TypeRootCA {
		parentCert, parentKey, issuerSerial, err = s.resolveIssuer(ctx, req.IssuerID)
		if err != nil {
			return sqlc.Certificate{}, err
		}
	}

	cert, err := pki.IssueCertificate(pki.CertOptions{
		Type:       req.Type,
		Subject:    req.Subject,
		SANs:       req.SANs,
		TTLInHours: hours,
		KeyPair: &pki.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: parentCert,
		ParentKey:  parentKey,
		Usages: &pki.KeyUsageConfig{
			KeyUsages:    crypto.ParseKeyUsages(req.KeyUsages),
			ExtKeyUsages: crypto.ParseExtKeyUsages(req.ExtKeyUsages),
		},
		PathLen: req.PathLen,
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to issue certificate: %w", err)
	}

	return s.storeCertificate(ctx, s.q, cert, req.Type, dbKey.ID, issuerSerial)
}

// ListCertificates returns certificates matching the given filters.
func (s *Service) ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]CertificateSummary, error) {
	statusFilter := sql.NullString{String: req.Status, Valid: req.Status != ""}
	typeFilter := sql.NullString{String: req.Type, Valid: req.Type != ""}

	var summaries []CertificateSummary

	if req.Limit == 0 && req.Offset == 0 {
		certs, err := s.q.ListAllCertificates(ctx, sqlc.ListAllCertificatesParams{
			Status: statusFilter,
			Type:   typeFilter,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch certificates from DB: %w", err)
		}
		for _, c := range certs {
			summaries = append(summaries, CertificateSummary{
				ID:           c.ID,
				SerialNumber: c.SerialNumber,
				CommonName:   c.CommonName,
				Type:         c.Type,
				Status:       c.Status,
				CreatedAt:    c.CreatedAt.Time,
			})
		}
		return summaries, nil
	}

	certs, err := s.q.ListCertificates(ctx, sqlc.ListCertificatesParams{
		Status: statusFilter,
		Type:   typeFilter,
		Limit:  int64(req.Limit),
		Offset: int64(req.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from DB: %w", err)
	}
	for _, c := range certs {
		summaries = append(summaries, CertificateSummary{
			ID:           c.ID,
			SerialNumber: c.SerialNumber,
			CommonName:   c.CommonName,
			Type:         c.Type,
			Status:       c.Status,
			CreatedAt:    c.CreatedAt.Time,
		})
	}
	return summaries, nil
}

// GetCertificate returns the raw stored record for a certificate.
func (s *Service) GetCertificate(ctx context.Context, id int64) (sqlc.Certificate, error) {
	rec, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	return rec, nil
}

// GetCertificateSerialNumber returns the serial number of a stored certificate.
func (s *Service) GetCertificateSerialNumber(ctx context.Context, id int64) (string, error) {
	return s.q.GetCertificateSerialNumberByID(ctx, id)
}

// GetParsedCertificate returns the parsed X.509 certificate for a stored record.
func (s *Service) GetParsedCertificate(ctx context.Context, id int64) (*x509.Certificate, error) {
	rec, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	return parseCertificateRecord(rec)
}

// RevokeCertificate marks a certificate as revoked with the given reason.
func (s *Service) RevokeCertificate(ctx context.Context, id int64, reason string) error {
	dbCert, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	if dbCert.IsRevoked.Int64 == 1 {
		return fmt.Errorf("certificate with ID %d is already revoked", id)
	}

	revReasonCode, err := crypto.ParseRevocationReason(reason)
	if err != nil {
		return err
	}

	_, err = s.q.RevokeCertificate(ctx, sqlc.RevokeCertificateParams{
		Status:           "REVOKED",
		IsRevoked:        sql.NullInt64{Int64: 1, Valid: true},
		RevocationTime:   sql.NullTime{Time: time.Now(), Valid: true},
		RevocationReason: sql.NullInt64{Int64: int64(revReasonCode), Valid: true},
		SerialNumber:     dbCert.SerialNumber,
	})
	if err != nil {
		return fmt.Errorf("failed to Revoke Certificate: %w", err)
	}

	return nil
}

// RotateCertificate issues a replacement certificate with a new key pair and
// revokes the previous one atomically.
func (s *Service) RotateCertificate(ctx context.Context, req RotateRequest) (sqlc.Certificate, error) {
	dbCert, err := s.getCertificateRecord(ctx, req.ID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	cert, err := parseCertificateRecord(dbCert)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyPair, err := s.q.GetKeyByID(ctx, req.KeyID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch Key from DB: %w", err)
	}
	privateKey, publicKey, err := parseKeyRecord(keyPair)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to parse keys: %w", err)
	}

	certType := pki.CertType(dbCert.Type)

	if dbCert.IsRevoked.Valid && dbCert.IsRevoked.Int64 == 1 {
		return sqlc.Certificate{}, fmt.Errorf("failed to rotate certificate: certificate is revoked")
	}

	var issuerCert *x509.Certificate
	var issuerPrivateKey any
	var issuerSerial string

	if certType != pki.TypeRootCA {
		if req.IssuerID == 0 {
			return sqlc.Certificate{}, fmt.Errorf("issuer ID (--iss) is required when rotating Intermediate or Leaf certificates")
		}
		issuerCert, issuerPrivateKey, issuerSerial, err = s.resolveIssuer(ctx, req.IssuerID)
		if err != nil {
			return sqlc.Certificate{}, err
		}
		if time.Now().After(issuerCert.NotAfter) {
			return sqlc.Certificate{}, fmt.Errorf("failed to rotate certificate: specified issuer (ID: %d) has expired", req.IssuerID)
		}
	}

	var pathLen *int
	if certType == pki.TypeIntermediate {
		if cert.MaxPathLenZero {
			zero := 0
			pathLen = &zero
		} else if cert.MaxPathLen > 0 {
			pl := cert.MaxPathLen
			pathLen = &pl
		}
	}

	ttlHours := int(cert.NotAfter.Sub(cert.NotBefore).Hours())

	newCert, err := pki.IssueCertificate(pki.CertOptions{
		Type:    certType,
		Subject: cert.Subject,
		SANs: pki.SANs{
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
			IPAddresses:    cert.IPAddresses,
			URIs:           cert.URIs,
		},
		TTLInHours: ttlHours,
		KeyPair: &pki.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &pki.KeyUsageConfig{
			KeyUsages:    crypto.ParseKeyUsages(crypto.MarshalKeyUsage(cert.KeyUsage)),
			ExtKeyUsages: crypto.ParseExtKeyUsages(crypto.MarshalExtKeyUsages(cert.ExtKeyUsage)),
		},
		PathLen: pathLen,
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to issue rotated Certificate: %w", err)
	}

	var created sqlc.Certificate
	err = store.RunInTx(ctx, s.db, func(txQuerier sqlc.Querier) error {
		var txErr error
		created, txErr = s.storeCertificate(ctx, txQuerier, newCert, certType, req.KeyID, issuerSerial)
		if txErr != nil {
			return fmt.Errorf("failed to insert new rotated Certificate in DB: %w", txErr)
		}

		_, txErr = txQuerier.UpdateCertificate(ctx, sqlc.UpdateCertificateParams{
			Status:           sql.NullString{String: "REVOKED", Valid: true},
			IsRevoked:        sql.NullInt64{Int64: 1, Valid: true},
			RevocationTime:   sql.NullTime{Time: time.Now(), Valid: true},
			RevocationReason: sql.NullInt64{Int64: 4, Valid: true},
			SerialNumber:     dbCert.SerialNumber,
		})
		if txErr != nil {
			return fmt.Errorf("failed to update old Certificate status in DB: %w", txErr)
		}

		return nil
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	return created, nil
}

// DeleteCertificate removes a certificate from the database.
func (s *Service) DeleteCertificate(ctx context.Context, id int64) error {
	if _, err := s.getCertificateRecord(ctx, id); err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	if err := s.q.DeleteCertificateByID(ctx, id); err != nil {
		return fmt.Errorf("failed to delete certificate from DB: %w", err)
	}
	return nil
}

// VerifyCertificateChain builds and cryptographically verifies the trust chain
// for a certificate, returning the ordered chain (leaf first).
func (s *Service) VerifyCertificateChain(ctx context.Context, id int64) ([]*x509.Certificate, error) {
	cert, err := s.GetParsedCertificate(ctx, id)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{cert}
	workingCert := cert

	const maxChainDepth = 10
	for depth := 0; depth < maxChainDepth; depth++ {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			break
		}

		if len(workingCert.AuthorityKeyId) == 0 {
			return nil, fmt.Errorf("Verification Failed: Chain broken. Certificate '%s' is not self-signed but lacks an Authority Key Identifier extension", workingCert.Subject.CommonName)
		}

		akidHex := fmt.Sprintf("%x", workingCert.AuthorityKeyId)

		parentDBCert, err := s.q.GetCertificateBySKID(ctx, akidHex)
		if err != nil {
			return nil, fmt.Errorf("Verification Failed: Trust chain broken. Authority Certificate with SKID [%s] (Issuer: %s) could not be found in the system: %w", akidHex, workingCert.Issuer.CommonName, err)
		}

		if parentDBCert.CommonName != "" && workingCert.Issuer.CommonName != "" && parentDBCert.CommonName != workingCert.Issuer.CommonName {
			return nil, fmt.Errorf("Verification Failed: Trust chain broken. Resolved parent certificate '%s' does not match expected issuer '%s'", parentDBCert.CommonName, workingCert.Issuer.CommonName)
		}

		parentCert, err := parseCertificateRecord(parentDBCert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse parent certificate: %w", err)
		}
		if workingCert.Issuer.String() != "" && parentCert.Subject.String() != workingCert.Issuer.String() {
			return nil, fmt.Errorf("Verification Failed: Trust chain broken. Resolved parent subject '%s' does not match expected issuer '%s'", parentCert.Subject.String(), workingCert.Issuer.String())
		}

		if err := workingCert.CheckSignatureFrom(parentCert); err != nil {
			return nil, fmt.Errorf("Verification Failed: Cryptographic signature mismatch between %s and issuer %s: %w", workingCert.Subject.CommonName, parentCert.Subject.CommonName, err)
		}

		chain = append(chain, parentCert)
		workingCert = parentCert

		if depth == maxChainDepth-1 {
			return nil, fmt.Errorf("Verification Failed: Exceeded maximum allowed chain depth (%d)", maxChainDepth)
		}
	}

	now := time.Now()
	for _, c := range chain {
		if now.Before(c.NotBefore) {
			return nil, fmt.Errorf("Verification Failed: Certificate '%s' is not active yet (Valid from: %s)", c.Subject.CommonName, c.NotBefore.Format("2006-01-02 15:04:05 UTC"))
		}
		if now.After(c.NotAfter) {
			return nil, fmt.Errorf("Verification Failed: Certificate '%s' expired on %s", c.Subject.CommonName, c.NotAfter.Format("2006-01-02 15:04:05 UTC"))
		}
	}

	rootCert := chain[len(chain)-1]
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return nil, fmt.Errorf("Verification Failed: Root certificate is self-signed but possesses a corrupt or invalid self-signature: %w", err)
	}

	return chain, nil
}

// ValidateCertificate runs structural and policy checks on a stored certificate.
func (s *Service) ValidateCertificate(ctx context.Context, id int64) (pki.ValidationResult, error) {
	cert, err := s.GetParsedCertificate(ctx, id)
	if err != nil {
		return pki.ValidationResult{}, err
	}
	return pki.ValidateCertificate(cert), nil
}

// DiffCertificates compares two stored certificates.
func (s *Service) DiffCertificates(ctx context.Context, id1, id2 int64) (DiffResult, error) {
	cert1, err := s.GetParsedCertificate(ctx, id1)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch certificate ID %d: %w", id1, err)
	}
	cert2, err := s.GetParsedCertificate(ctx, id2)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch certificate ID %d: %w", id2, err)
	}

	return DiffResult{
		Name1: cert1.Subject.CommonName,
		Name2: cert2.Subject.CommonName,
		Diffs: pki.CompareCertificates(cert1, cert2),
	}, nil
}

// ExportCertificate writes a single certificate to disk in PEM or DER format
// and returns the written path.
func (s *Service) ExportCertificate(ctx context.Context, req ExportRequest) (string, error) {
	dbCert, err := s.getCertificateRecord(ctx, req.ID)
	if err != nil {
		return "", fmt.Errorf("failed to get Certificate from db: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "pem"
	}

	var data []byte
	var ext string

	switch format {
	case "pem":
		ext = ".pem"
		data = []byte(dbCert.CertificatePem)
	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCert.CertificatePem))
		if block == nil {
			return "", errors.New("failed to decode PEM formatted Certificate into DER")
		}
		data = block.Bytes
	default:
		return "", fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", req.Format)
	}

	certFilePath, err := crypto.ResolveDestinationPath(req.Path, crypto.ToSnakeCase(dbCert.CommonName), ext)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	if err := writeFile(certFilePath, data, 0o600); err != nil {
		return "", err
	}

	return certFilePath, nil
}

// ExportCertificateChain writes the full certificate chain to disk in PEM or
// PKCS#7 format and returns the written path.
func (s *Service) ExportCertificateChain(ctx context.Context, req ExportRequest) (string, error) {
	ext := ".pem"
	if req.Format == "pkcs7" {
		ext = ".p7b"
	}

	dbCert, err := s.getCertificateRecord(ctx, req.ID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	cert, err := parseCertificateRecord(dbCert)
	if err != nil {
		return "", err
	}

	chain, err := s.buildChain(ctx, cert)
	if err != nil {
		return "", err
	}

	var data []byte
	if req.Format == "pkcs7" {
		data, err = pki.GetPKCS7Chain(cert, chain)
	} else {
		data, err = pki.GetPEMChain(cert, chain)
	}
	if err != nil {
		return "", err
	}

	defaultFileName := crypto.SanitizeFilename(cert.Subject.CommonName, "chain") + "_chain"
	outPath, err := crypto.ResolveDestinationPath(req.Path, crypto.ToSnakeCase(defaultFileName), ext)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	if err := writeFile(outPath, data, 0o600); err != nil {
		return "", err
	}

	return outPath, nil
}

// ExportCertificateBundle writes a certificate + private key bundle to disk in
// PKCS#12 or PEM format and returns the written path.
func (s *Service) ExportCertificateBundle(ctx context.Context, req ExportBundleRequest) (string, error) {
	ext := ".p12"
	if req.Format == "pem" {
		ext = ".pem"
	}

	dbCert, err := s.getCertificateRecord(ctx, req.ID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	cert, err := parseCertificateRecord(dbCert)
	if err != nil {
		return "", err
	}

	keyRecord, err := s.q.GetKeyByID(ctx, dbCert.KeyID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Keys from DB: %w", err)
	}
	privateKey, _, err := parseKeyRecord(keyRecord)
	if err != nil {
		return "", err
	}

	chain, err := s.buildChain(ctx, cert)
	if err != nil {
		return "", err
	}

	var data []byte
	if req.Format == "pkcs12" {
		data, err = pkcs12.Modern.Encode(privateKey, cert, chain, req.PassPhrase)
		if err != nil {
			return "", fmt.Errorf("failed to encode PKCS#12 bundle: %w", err)
		}
	} else {
		data, err = pki.GetPEMBundle(privateKey, cert, chain)
		if err != nil {
			return "", err
		}
	}

	defaultFileName := crypto.SanitizeFilename(cert.Subject.CommonName, "bundle") + "_bundle"
	outPath, err := crypto.ResolveDestinationPath(req.Path, crypto.ToSnakeCase(defaultFileName), ext)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	if err := writeFile(outPath, data, 0o600); err != nil {
		return "", err
	}

	return outPath, nil
}

// writeFile creates any missing parent directories and writes data to path.
func writeFile(path string, data []byte, perm os.FileMode) error {
	targetDir := filepath.Dir(path)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("could not write to file %s: %w", path, err)
	}
	return nil
}
