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
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

// GenerateCRLRequest describes a CRL to generate for an issuer.
type GenerateCRLRequest struct {
	IssuerID int64
	TTL      string
}

// ListCRLsRequest filters and paginates a CRL listing.
type ListCRLsRequest struct {
	Limit    int
	Offset   int
	IssuerID int64
}

// GenerateCRL builds and signs a new revocation list for the given issuer.
func (s *Service) GenerateCRL(ctx context.Context, req GenerateCRLRequest) (sqlc.Crl, error) {
	issuerDBCert, err := s.getCertificateRecord(ctx, req.IssuerID)
	if err != nil {
		return sqlc.Crl{}, err
	}

	issuerCert, err := parseCertificateRecord(issuerDBCert)
	if err != nil {
		return sqlc.Crl{}, err
	}
	if !issuerCert.IsCA {
		return sqlc.Crl{}, fmt.Errorf("failed to generate CRL: issuer is not a CA certificate")
	}
	if issuerDBCert.IsRevoked.Valid && issuerDBCert.IsRevoked.Int64 == 1 {
		return sqlc.Crl{}, fmt.Errorf("failed to generate CRL: Issuer itself is Revoked")
	}

	revokedCerts, err := s.q.ListAllRevokedCertificates(ctx, sql.NullString{String: issuerDBCert.SerialNumber, Valid: true})
	if err != nil {
		return sqlc.Crl{}, fmt.Errorf("failed to fetch Revoked Certificates: %w", err)
	}
	if len(revokedCerts) <= 0 {
		return sqlc.Crl{}, fmt.Errorf("no Certificate has been Revoked from this Issuer")
	}

	var nextCRLNumber int64 = 1
	latestCRL, err := s.q.GetLatestCRL(ctx, issuerDBCert.ID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return sqlc.Crl{}, fmt.Errorf("failed to fetch latest CRL: %w", err)
		}
	} else {
		nextCRLNumber = int64(latestCRL.CrlNumber) + 1
	}

	issuerKey, err := s.q.GetKeyByID(ctx, issuerDBCert.KeyID)
	if err != nil {
		return sqlc.Crl{}, fmt.Errorf("failed to fetch issuer private key (%d): %w", issuerDBCert.KeyID, err)
	}
	rawKey, _, err := parseKeyRecord(issuerKey)
	if err != nil {
		return sqlc.Crl{}, err
	}
	issuerPrivateKey, ok := rawKey.(stdcrypto.Signer)
	if !ok {
		return sqlc.Crl{}, errors.New("parsed private key does not implement crypto.Signer")
	}

	now := time.Now()
	ttlHours, err := crypto.ParseTTLToHours(req.TTL)
	if err != nil {
		return sqlc.Crl{}, err
	}
	nextUpdate := now.Add(time.Duration(ttlHours) * time.Hour)

	revokedInputs, err := mapRevokedCerts(revokedCerts, now)
	if err != nil {
		return sqlc.Crl{}, err
	}

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  issuerCert.SignatureAlgorithm,
		Number:              big.NewInt(nextCRLNumber),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedInputs,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, issuerCert, issuerPrivateKey)
	if err != nil {
		return sqlc.Crl{}, fmt.Errorf("failed to sign CRL: %w", err)
	}

	crlPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return s.q.CreateCRL(ctx, sqlc.CreateCRLParams{
		Name:       formatCRLName(issuerCert.Subject.CommonName, now),
		CrlNumber:  nextCRLNumber,
		IssuerID:   issuerDBCert.ID,
		ThisUpdate: now,
		NextUpdate: nextUpdate,
		CrlPem:     string(crlPEMBlock),
	})
}

// ListCRLs returns CRLs for the given issuer.
func (s *Service) ListCRLs(ctx context.Context, req ListCRLsRequest) ([]sqlc.Crl, error) {
	if req.Limit == 0 && req.Offset == 0 {
		crls, err := s.q.ListAllCRLs(ctx, req.IssuerID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch CRLs from DB: %w", err)
		}
		return crls, nil
	}

	crls, err := s.q.ListCRLs(ctx, sqlc.ListCRLsParams{
		IssuerID: req.IssuerID,
		Limit:    int64(req.Limit),
		Offset:   int64(req.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRLs from DB: %w", err)
	}
	return crls, nil
}

// GetCRL returns the raw stored record for a CRL.
func (s *Service) GetCRL(ctx context.Context, id int64) (sqlc.Crl, error) {
	rec, err := s.q.GetCRLByID(ctx, id)
	if err != nil {
		return sqlc.Crl{}, fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}
	return rec, nil
}

// GetParsedCRL returns the parsed X.509 revocation list for a stored record.
func (s *Service) GetParsedCRL(ctx context.Context, id int64) (*x509.RevocationList, error) {
	rec, err := s.q.GetCRLByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}
	return crypto.ParseCRL([]byte(rec.CrlPem))
}

// VerifyCRL verifies the cryptographic signature of a CRL against its issuer.
func (s *Service) VerifyCRL(ctx context.Context, id int64) (*x509.RevocationList, error) {
	crlRecord, err := s.q.GetCRLByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from DB: %w", err)
	}

	issuerDBCert, err := s.getCertificateRecord(ctx, crlRecord.IssuerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer certificate (%d) for verification: %w", crlRecord.ID, err)
	}

	parsedCRL, err := crypto.ParseCRL([]byte(crlRecord.CrlPem))
	if err != nil {
		return nil, err
	}
	issuerCert, err := parseCertificateRecord(issuerDBCert)
	if err != nil {
		return nil, err
	}

	if err := parsedCRL.CheckSignatureFrom(issuerCert); err != nil {
		return nil, fmt.Errorf(" CRL cryptographic verification failed: signature mismatch: %w", err)
	}

	return parsedCRL, nil
}

// ValidateCRL runs sanity and validity period checks on a stored CRL.
func (s *Service) ValidateCRL(ctx context.Context, id int64) (pki.ValidationResult, error) {
	crl, err := s.GetParsedCRL(ctx, id)
	if err != nil {
		return pki.ValidationResult{}, err
	}
	return pki.ValidateCRL(crl), nil
}

// DiffCRLs compares two stored CRLs.
func (s *Service) DiffCRLs(ctx context.Context, id1, id2 int64) (DiffResult, error) {
	rec1, err := s.q.GetCRLByID(ctx, id1)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch CRL ID %d: %w", id1, err)
	}
	rec2, err := s.q.GetCRLByID(ctx, id2)
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to fetch CRL ID %d: %w", id2, err)
	}

	crl1, err := crypto.ParseCRL([]byte(rec1.CrlPem))
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to parse CRL ID %d: %w", id1, err)
	}
	crl2, err := crypto.ParseCRL([]byte(rec2.CrlPem))
	if err != nil {
		return DiffResult{}, fmt.Errorf("failed to parse CRL ID %d: %w", id2, err)
	}

	return DiffResult{
		Name1: rec1.Name,
		Name2: rec2.Name,
		Diffs: pki.CompareCRLs(crl1, crl2),
	}, nil
}

// ExportCRL writes a CRL to disk in PEM or DER format and returns the path.
func (s *Service) ExportCRL(ctx context.Context, req ExportRequest) (string, error) {
	crl, err := s.q.GetCRLByID(ctx, req.ID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CRL from DB: %w", err)
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
		data = []byte(crl.CrlPem)
	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(crl.CrlPem))
		if block == nil {
			return "", errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes
	default:
		return "", fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", req.Format)
	}

	defaultFilename := fmt.Sprintf("%s_crl", crypto.ToSnakeCase(crl.Name))
	crlFilePath, err := crypto.ResolveDestinationPath(req.Path, defaultFilename, ext)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	if err := writeFile(crlFilePath, data, 0o644); err != nil {
		return "", err
	}

	return crlFilePath, nil
}

func mapRevokedCerts(revokedCerts []sqlc.Certificate, now time.Time) ([]pkix.RevokedCertificate, error) {
	var revokedInputs []pkix.RevokedCertificate

	// Object Identifier (OID) for CRL Reason Code extension.
	oidExtensionReasonCode := []int{2, 5, 29, 21}

	for _, rc := range revokedCerts {
		serialInt := new(big.Int)
		_, success := serialInt.SetString(rc.SerialNumber, 16)
		if !success {
			_, success = serialInt.SetString(rc.SerialNumber, 10)
			if !success {
				return nil, fmt.Errorf("failed to parse certificate serial number: %s", rc.SerialNumber)
			}
		}

		revTime := now
		if rc.RevocationTime.Valid {
			revTime = rc.RevocationTime.Time
		}

		var extensions []pkix.Extension

		if rc.RevocationReason.Valid && rc.RevocationReason.Int64 > 0 {
			// ASN.1 ENUMERATED value encoding for the reason code.
			reasonBytes := []byte{0x0a, 0x01, byte(rc.RevocationReason.Int64)}

			extensions = append(extensions, pkix.Extension{
				Id:       oidExtensionReasonCode,
				Critical: false,
				Value:    reasonBytes,
			})
		}

		revokedInputs = append(revokedInputs, pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: revTime,
			Extensions:     extensions,
		})
	}
	return revokedInputs, nil
}

// formatCRLName creates an identifier string like "MyCA_20260720_045357".
func formatCRLName(commonName string, now time.Time) string {
	sanitizedName := strings.ReplaceAll(commonName, " ", "_")
	timestamp := now.Format("20060102_150405")
	return fmt.Sprintf("%s_%s", sanitizedName, timestamp)
}
