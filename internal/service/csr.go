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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	store "github.com/tassok-wasi/pkit/internal/store"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

// GenerateCSRRequest describes a certificate signing request to generate.
type GenerateCSRRequest struct {
	Subject pkix.Name
	SANs    pki.SANs
	KeyType string
	KeyID   string
}

// ListCSRsRequest filters and paginates a CSR listing.
type ListCSRsRequest struct {
	Limit  int
	Offset int
	Status string
}

// CSRSummary is a normalized row for listing CSRs.
type CSRSummary struct {
	ID            string
	CommonName    string
	KeyID         string
	Status        string
	CertificateID sql.NullString
}

// SignCSRRequest describes signing a pending CSR into a certificate.
type SignCSRRequest struct {
	ID           string
	Type         string
	TTL          string
	KeyUsages    []string
	ExtKeyUsages []string
	PathLen      *int
	IssuerID     string
}

// CSRVerifyResult carries the outcome of a CSR integrity check.
type CSRVerifyResult struct {
	CSR       *x509.CertificateRequest
	KeyDetail string
	Issues    []string
}

// GenerateCSR builds a certificate signing request and persists it.
func (s *Service) GenerateCSR(ctx context.Context, req GenerateCSRRequest) (created sqlc.Csr, retErr error) {
	dbKey, autoKey, err := s.resolveKey(ctx, req.KeyID, req.Subject.CommonName, pki.TypeLeaf, req.KeyType)
	if err != nil {
		return sqlc.Csr{}, fmt.Errorf("failed to resolve key for CSR: %w", err)
	}
	if autoKey {
		defer func() {
			if retErr != nil {
				_ = s.q.DeleteKeyByID(ctx, dbKey.ID)
			}
		}()
	}

	privateKey, _, err := parseKeyRecord(dbKey)
	if err != nil {
		return sqlc.Csr{}, err
	}

	keyType := strings.ToLower(strings.TrimSpace(dbKey.Algorithm))
	if keyType == "" {
		keyType = strings.ToLower(strings.TrimSpace(req.KeyType))
		if keyType == "" {
			keyType = "ecdsa-256"
		}
	}
	signatureAlgo, err := crypto.GetSignatureAlgorithm(keyType)
	if err != nil {
		return sqlc.Csr{}, err
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            req.Subject,
		DNSNames:           req.SANs.DNSNames,
		EmailAddresses:     req.SANs.EmailAddresses,
		IPAddresses:        req.SANs.IPAddresses,
		URIs:               req.SANs.URIs,
		SignatureAlgorithm: signatureAlgo,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return sqlc.Csr{}, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPem, err := crypto.EncodeToPem(csr, "CERTIFICATE REQUEST")
	if err != nil {
		return sqlc.Csr{}, err
	}

	created, retErr = createWithIDRetry("csrs", func() (sqlc.Csr, error) {
		return s.q.CreateCSR(ctx, sqlc.CreateCSRParams{
			CommonName:    csrTemplate.Subject.CommonName,
			KeyID:         dbKey.ID,
			Status:        "PENDING",
			CsrPem:        string(csrPem),
			CertificateID: sql.NullString{},
		})
	})
	return created, retErr
}

// ListCSRs returns CSRs matching the given filters.
func (s *Service) ListCSRs(ctx context.Context, req ListCSRsRequest) ([]CSRSummary, error) {
	statusFilter := sql.NullString{String: req.Status, Valid: req.Status != ""}

	var summaries []CSRSummary

	if req.Limit == 0 && req.Offset == 0 {
		csrs, err := s.q.ListAllCSRs(ctx, statusFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch CSRs from DB: %w", err)
		}
		for _, c := range csrs {
			summaries = append(summaries, CSRSummary{
				ID:            c.ID,
				CommonName:    c.CommonName,
				KeyID:         c.KeyID,
				Status:        c.Status,
				CertificateID: c.CertificateID,
			})
		}
		return summaries, nil
	}

	csrs, err := s.q.ListCSRs(ctx, sqlc.ListCSRsParams{
		Status: statusFilter,
		Limit:  int64(req.Limit),
		Offset: int64(req.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CSRs from DB: %w", err)
	}
	for _, c := range csrs {
		summaries = append(summaries, CSRSummary{
			ID:            c.ID,
			CommonName:    c.CommonName,
			KeyID:         c.KeyID,
			Status:        c.Status,
			CertificateID: c.CertificateID,
		})
	}
	return summaries, nil
}

// GetCSR returns the raw stored record for a CSR.
func (s *Service) GetCSR(ctx context.Context, id string) (sqlc.Csr, error) {
	rec, err := s.q.GetCSRByID(ctx, id)
	if err != nil {
		return sqlc.Csr{}, fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}
	return rec, nil
}

// GetParsedCSR returns the parsed X.509 certificate request for a stored record.
func (s *Service) GetParsedCSR(ctx context.Context, id string) (*x509.CertificateRequest, error) {
	rec, err := s.q.GetCSRByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}
	return crypto.ParseCSR(rec.CsrPem)
}

// VerifyCSR checks the self-signature, key strength, and stored-key match of a CSR.
func (s *Service) VerifyCSR(ctx context.Context, id string) (CSRVerifyResult, error) {
	csrRecord, err := s.q.GetCSRByID(ctx, id)
	if err != nil {
		return CSRVerifyResult{}, fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	parsedCSR, err := crypto.ParseCSR(csrRecord.CsrPem)
	if err != nil {
		return CSRVerifyResult{}, err
	}

	var issues []string

	if err := parsedCSR.CheckSignature(); err != nil {
		issues = append(issues, fmt.Sprintf("Signature: INVALID (%v)", err))
	}

	keyDetail := "Unknown"
	switch pub := parsedCSR.PublicKey.(type) {
	case *rsa.PublicKey:
		bitLen := pub.N.BitLen()
		keyDetail = fmt.Sprintf("RSA %d-bit", bitLen)
		if bitLen < 2048 {
			issues = append(issues, fmt.Sprintf("Key Strength: WEAK (%d bits < 2048 required)", bitLen))
		}
	default:
		keyDetail = fmt.Sprintf("%T", pub)
	}

	if csrRecord.KeyID != "" {
		keyRecord, err := s.q.GetKeyByID(ctx, csrRecord.KeyID)
		if err == nil {
			keyBlock, _ := pem.Decode([]byte(keyRecord.PublicKeyPem))
			if keyBlock != nil {
				storedPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
				if err == nil {
					if !pubKeysEqual(parsedCSR.PublicKey, storedPubKey) {
						issues = append(issues, "Key Match: Public key does NOT match stored key pair")
					}
				}
			}
		}
	}

	if parsedCSR.Subject.CommonName == "" {
		issues = append(issues, "Subject: Missing Common Name (CN)")
	}

	return CSRVerifyResult{
		CSR:       parsedCSR,
		KeyDetail: keyDetail,
		Issues:    issues,
	}, nil
}

// ValidateCSR runs sanity and policy checks on a stored CSR.
func (s *Service) ValidateCSR(ctx context.Context, id string) (pki.ValidationResult, error) {
	csr, err := s.GetParsedCSR(ctx, id)
	if err != nil {
		return pki.ValidationResult{}, err
	}
	return pki.ValidateCSR(csr), nil
}

// DiffCSRs compares two stored CSRs.
func (s *Service) DiffCSRs(ctx context.Context, id1, id2 string) (DiffResult, error) {
	rec1, err := s.q.GetCSRByID(ctx, id1)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch CSR ID %s: %w", id1, err)
	}
	rec2, err := s.q.GetCSRByID(ctx, id2)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch CSR ID %s: %w", id2, err)
	}

	csr1, err := crypto.ParseCSR(rec1.CsrPem)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to parse CSR ID %s: %w", id1, err)
	}
	csr2, err := crypto.ParseCSR(rec2.CsrPem)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to parse CSR ID %s: %w", id2, err)
	}

	return DiffResult{
		Name1: csr1.Subject.CommonName,
		Name2: csr2.Subject.CommonName,
		Diffs: pki.CompareCSRs(csr1, csr2),
	}, nil
}

// SignCSR issues a certificate from a pending CSR and marks the CSR as signed.
func (s *Service) SignCSR(ctx context.Context, req SignCSRRequest) (sqlc.Certificate, error) {
	hours, err := crypto.ParseTTLToHours(req.TTL)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("invalid TTL value: %w", err)
	}

	dbCsr, err := s.q.GetCSRByID(ctx, req.ID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}
	if dbCsr.Status != "PENDING" {
		return sqlc.Certificate{}, fmt.Errorf("CSR %s is not pending (status: %s)", dbCsr.ID, dbCsr.Status)
	}

	csr, err := crypto.ParseCSR(dbCsr.CsrPem)
	if err != nil {
		return sqlc.Certificate{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return sqlc.Certificate{}, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	keyRecord, err := s.q.GetKeyByID(ctx, dbCsr.KeyID)
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to fetch CSR key from DB: %w", err)
	}
	_, storedPublicKey, err := parseKeyRecord(keyRecord)
	if err != nil {
		return sqlc.Certificate{}, err
	}
	if !pubKeysEqual(csr.PublicKey, storedPublicKey) {
		return sqlc.Certificate{}, errors.New("CSR public key does not match the associated stored key pair")
	}

	certType := pki.CertType(req.Type)
	if certType != pki.TypeLeaf && certType != pki.TypeIntermediate {
		return sqlc.Certificate{}, fmt.Errorf("unsupported certificate type for CSR signing: %s", req.Type)
	}

	issuerCert, issuerPrivateKey, issuerSerial, err := s.resolveIssuer(ctx, req.IssuerID)
	if err != nil {
		return sqlc.Certificate{}, err
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
		Type:    certType,
		Subject: csr.Subject,
		SANs: pki.SANs{
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			EmailAddresses: csr.EmailAddresses,
			URIs:           csr.URIs,
		},
		TTLInHours: hours,
		KeyPair: &pki.KeyPair{
			PublicKey: csr.PublicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &pki.KeyUsageConfig{
			KeyUsages:    keyUsages,
			ExtKeyUsages: extKeyUsages,
		},
		PathLen: req.PathLen,
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("failed to issue certificate: %w", err)
	}

	var created sqlc.Certificate
	err = store.RunInTx(ctx, s.db, func(txQuerier sqlc.Querier) error {
		var txErr error
		created, txErr = s.storeCertificate(ctx, txQuerier, cert, certType, dbCsr.KeyID, issuerSerial)
		if txErr != nil {
			return fmt.Errorf("failed to create Certificate in DB: %w", txErr)
		}

		updated, txErr := txQuerier.UpdateCSRStatus(ctx, sqlc.UpdateCSRStatusParams{
			Status:        "SIGNED",
			CertificateID: sql.NullString{String: created.ID, Valid: true},
			ID:            dbCsr.ID,
		})
		if txErr != nil {
			return fmt.Errorf("failed to update csr status: %w", txErr)
		}
		if updated != 1 {
			return fmt.Errorf("CSR %s is no longer pending", dbCsr.ID)
		}

		return nil
	})
	if err != nil {
		return sqlc.Certificate{}, fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	return created, nil
}

// ExportCSR writes a CSR to disk in PEM or DER format and returns the path.
func (s *Service) ExportCSR(ctx context.Context, req ExportRequest) (string, error) {
	dbCsr, err := s.q.GetCSRByID(ctx, req.ID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CSR from DB: %w", err)
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
		data = []byte(dbCsr.CsrPem)
	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCsr.CsrPem))
		if block == nil {
			return "", errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes
	default:
		return "", fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", req.Format)
	}

	defaultFilename := fmt.Sprintf("%s_csr", crypto.ToSnakeCase(dbCsr.CommonName))
	csrFilePath, err := crypto.ResolveDestinationPath(req.Path, defaultFilename, ext)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	if err := writeFile(csrFilePath, data, 0o644); err != nil {
		return "", err
	}

	return csrFilePath, nil
}

// pubKeysEqual compares two public keys for cryptographic equality.
func pubKeysEqual(a, b any) bool {
	switch keyA := a.(type) {
	case *rsa.PublicKey:
		keyB, ok := b.(*rsa.PublicKey)
		return ok && keyA.N.Cmp(keyB.N) == 0 && keyA.E == keyB.E
	case *ecdsa.PublicKey:
		keyB, ok := b.(*ecdsa.PublicKey)
		if !ok || keyA.Curve != keyB.Curve {
			return false
		}
		derA, errA := x509.MarshalPKIXPublicKey(keyA)
		derB, errB := x509.MarshalPKIXPublicKey(keyB)
		if errA != nil || errB != nil {
			return false
		}
		return bytes.Equal(derA, derB)
	case ed25519.PublicKey:
		keyB, ok := b.(ed25519.PublicKey)
		return ok && bytes.Equal(keyA, keyB)
	default:
		return false
	}
}
