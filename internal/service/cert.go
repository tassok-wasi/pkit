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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
	KeyID        string
	KeyType      string
	IssuerID     string
	KeyUsages    []string
	ExtKeyUsages []string
	PathLen      *int
}

// RotateRequest describes a certificate rotation.
type RotateRequest struct {
	ID       string
	IssuerID string
	KeyID    string
	KeyType  string
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
	ID           string
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
	ID     string
	Path   string
	Format string
}

// ExportBundleRequest describes a certificate + key bundle export.
type ExportBundleRequest struct {
	ID         string
	Path       string
	Format     string
	PassPhrase string
}

// IssueCertificate issues a Root CA, Intermediate CA, or Leaf certificate and
// persists it.
func (s *Service) IssueCertificate(ctx context.Context, req IssueRequest) (created sqlc.Certificate, retErr error) {
	hours, err := crypto.ParseTTLToHours(req.TTL)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, autoKey, err := s.resolveKey(ctx, req.KeyID, req.Subject.CommonName, req.Type, req.KeyType)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to resolve key for certificate: %w", err)
	}
	if autoKey {
		defer func() {
			if retErr != nil {
				_ = s.q.DeleteKeyByID(ctx, dbKey.ID)
			}
		}()
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

	keyUsages, err := crypto.ParseKeyUsages(req.KeyUsages)
	if err != nil {
		return sqlc.Certificate{}, err
	}
	extKeyUsages, err := crypto.ParseExtKeyUsages(req.ExtKeyUsages)
	if err != nil {
		return sqlc.Certificate{}, err
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
			KeyUsages:    keyUsages,
			ExtKeyUsages: extKeyUsages,
		},
		PathLen: req.PathLen,
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to issue certificate: %w", err)
	}

	created, retErr = s.storeCertificate(ctx, s.q, cert, req.Type, dbKey.ID, issuerSerial)
	return created, retErr
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
func (s *Service) GetCertificate(ctx context.Context, id string) (sqlc.Certificate, error) {
	rec, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	if rec.Status != "REVOKED" && time.Now().After(rec.NotAfter) {
		rec.Status = "EXPIRED"
	}
	return rec, nil
}

// GetCertificateSerialNumber returns the serial number of a stored certificate.
func (s *Service) GetCertificateSerialNumber(ctx context.Context, id string) (string, error) {
	return s.q.GetCertificateSerialNumberByID(ctx, id)
}

// GetParsedCertificate returns the parsed X.509 certificate for a stored record.
func (s *Service) GetParsedCertificate(ctx context.Context, id string) (*x509.Certificate, error) {
	rec, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	return parseCertificateRecord(rec)
}

// RevokeCertificate marks a certificate as revoked with the given reason.
func (s *Service) RevokeCertificate(ctx context.Context, id string, reason string) error {
	dbCert, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	if dbCert.IsRevoked.Int64 == 1 {
		return fmt.Errorf("certificate with ID %s is already revoked", id)
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
func (s *Service) RotateCertificate(ctx context.Context, req RotateRequest) (created sqlc.Certificate, retErr error) {
	dbCert, err := s.getCertificateRecord(ctx, req.ID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}
	cert, err := parseCertificateRecord(dbCert)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certType := pki.CertType(dbCert.Type)

	keyPair, autoKey, err := s.resolveKey(ctx, req.KeyID, cert.Subject.CommonName, certType, req.KeyType)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to resolve key for rotated certificate: %w", err)
	}
	if autoKey {
		defer func() {
			if retErr != nil {
				_ = s.q.DeleteKeyByID(ctx, keyPair.ID)
			}
		}()
	}
	privateKey, publicKey, err := parseKeyRecord(keyPair)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to parse keys: %w", err)
	}

	if dbCert.IsRevoked.Valid && dbCert.IsRevoked.Int64 == 1 {
		return sqlc.Certificate{}, fmt.Errorf("failed to rotate certificate: certificate is revoked")
	}

	var issuerCert *x509.Certificate
	var issuerPrivateKey any
	var issuerSerial string

	if certType != pki.TypeRootCA {
		if req.IssuerID == "" {
			return sqlc.Certificate{}, fmt.Errorf("issuer ID (--iss) is required when rotating Intermediate or Leaf certificates")
		}
		issuerCert, issuerPrivateKey, issuerSerial, err = s.resolveIssuer(ctx, req.IssuerID)
		if err != nil {
			return sqlc.Certificate{}, err
		}
		if time.Now().After(issuerCert.NotAfter) {
			return sqlc.Certificate{}, fmt.Errorf("failed to rotate certificate: specified issuer (ID: %s) has expired", req.IssuerID)
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

	keyUsages, err := crypto.ParseKeyUsages(crypto.MarshalKeyUsage(cert.KeyUsage))
	if err != nil {
		return sqlc.Certificate{}, err
	}
	extKeyUsages, err := crypto.ParseExtKeyUsages(crypto.MarshalExtKeyUsages(cert.ExtKeyUsage))
	if err != nil {
		return sqlc.Certificate{}, err
	}

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
			KeyUsages:    keyUsages,
			ExtKeyUsages: extKeyUsages,
		},
		PathLen: pathLen,
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to issue rotated Certificate: %w", err)
	}

	err = store.RunInTx(ctx, s.db, func(txQuerier sqlc.Querier) error {
		var txErr error
		created, txErr = s.storeCertificate(ctx, txQuerier, newCert, certType, keyPair.ID, issuerSerial)
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

	return created, retErr
}

// DeleteCertificate removes a certificate from the database.
func (s *Service) DeleteCertificate(ctx context.Context, id string) error {
	dbCert, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	dependents, err := s.q.CountCertificatesByIssuerSerialNumber(ctx, sql.NullString{String: dbCert.SerialNumber, Valid: true})
	if err != nil {
		return fmt.Errorf("failed to check certificate dependents: %w", err)
	}
	if dependents > 0 {
		return fmt.Errorf("cannot delete certificate: it is the issuer of %d certificate(s)", dependents)
	}

	if err := s.q.DeleteCertificateByID(ctx, id); err != nil {
		return fmt.Errorf("failed to delete certificate from DB: %w", err)
	}
	return nil
}

// VerifyCertificateChain builds and cryptographically verifies the trust chain
// for a certificate, returning the ordered chain (leaf first).
func (s *Service) VerifyCertificateChain(ctx context.Context, id string) ([]*x509.Certificate, error) {
	cert, err := s.GetParsedCertificate(ctx, id)
	if err != nil {
		return nil, err
	}

	var chain []*x509.Certificate

	if cert.Subject.String() == cert.Issuer.String() {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("root certificate self-signature verification failed: %w", err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, fmt.Errorf("root certificate is outside its validity period")
		}
		chain = []*x509.Certificate{cert}
	} else {
		parents, err := s.buildChain(ctx, cert)
		if err != nil {
			return nil, err
		}
		chain = append([]*x509.Certificate{cert}, parents...)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	if len(chain) > 2 {
		for _, parent := range chain[1 : len(chain)-1] {
			intermediates.AddCert(parent)
		}
	}

	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("trust chain verification failed: %w", err)
	}

	for i := 0; i < len(chain)-1; i++ {
		issuerDB, err := s.q.GetCertificateBySKID(ctx, hex.EncodeToString(chain[i].AuthorityKeyId))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve issuer for revocation check: %w", err)
		}
		crlRow, err := s.q.GetLatestCRL(ctx, issuerDB.ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer CRL: %w", err)
		}
		crl, err := crypto.ParseCRL([]byte(crlRow.CrlPem))
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer CRL: %w", err)
		}
		if err := crl.CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, fmt.Errorf("issuer CRL signature verification failed: %w", err)
		}
		if serialRevoked(crl, chain[i].SerialNumber) {
			return nil, fmt.Errorf("certificate %s is revoked", chain[i].Subject.CommonName)
		}
	}

	return chain, nil
}

func serialRevoked(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// ValidateCertificate runs structural and policy checks on a stored certificate.
func (s *Service) ValidateCertificate(ctx context.Context, id string) (pki.ValidationResult, error) {
	cert, err := s.GetParsedCertificate(ctx, id)
	if err != nil {
		return pki.ValidationResult{}, err
	}
	return pki.ValidateCertificate(cert), nil
}

// DiffCertificates compares two stored certificates.
func (s *Service) DiffCertificates(ctx context.Context, id1, id2 string) (DiffResult, error) {
	cert1, err := s.GetParsedCertificate(ctx, id1)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch certificate ID %s: %w", id1, err)
	}
	cert2, err := s.GetParsedCertificate(ctx, id2)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch certificate ID %s: %w", id2, err)
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
