// Copyright 2026 Tassok Imam Wasi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestGenerateCmd_Run(t *testing.T) {
	// Seed Issuer CA Key and Certificate
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "crl-gen-issuer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7001),
		Subject:               pkix.Name{CommonName: "CRL Gen Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	pem, _ := utils.EncodeToPem(der, "CERTIFICATE")

	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "7001",
		CommonName:     "CRL Gen Issuer CA",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "crl-gen-skid",
		Akid:           "crl-gen-akid",
		Status:         "ACTIVE",
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pem),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}

	// Seed a Revoked Certificate belonging to this Issuer
	_, err = testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:       "7002",
		CommonName:         "Revoked Leaf Cert",
		Type:               "LEAF",
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: "7001", Valid: true},
		Skid:               "rev-skid",
		Akid:               "crl-gen-skid",
		Status:             "REVOKED",
		IsRevoked:          sql.NullInt64{Int64: 1, Valid: true},
		NotBefore:          tmpl.NotBefore,
		NotAfter:           tmpl.NotAfter,
		CertificatePem:     string(pem),
	})
	if err != nil {
		t.Fatalf("failed to seed revoked cert: %v", err)
	}

	// Seed an Issuer CA that has no revoked certs
	dbCleanIssuer, _ := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "7003",
		CommonName:     "Clean Issuer CA",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "clean-skid",
		Akid:           "clean-akid",
		Status:         "ACTIVE",
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pem),
	})

	tests := []struct {
		name    string
		cmd     GenerateCmd
		wantErr bool
	}{
		{
			name: "successfully generate CRL for issuer with revoked certs",
			cmd: GenerateCmd{
				IssuerID: dbIssuerCert.ID,
				TTL:      "168h",
			},
			wantErr: false,
		},
		{
			name: "error when issuer has no revoked certificates",
			cmd: GenerateCmd{
				IssuerID: dbCleanIssuer.ID,
				TTL:      "168h",
			},
			wantErr: true,
		},
		{
			name: "invalid TTL string returns error",
			cmd: GenerateCmd{
				IssuerID: dbIssuerCert.ID,
				TTL:      "invalid_ttl",
			},
			wantErr: true,
		},
		{
			name: "non-existent issuer ID returns error",
			cmd: GenerateCmd{
				IssuerID: 999999,
				TTL:      "168h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatCRLName(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 4, 53, 57, 0, time.UTC)

	tests := []struct {
		name       string
		commonName string
		want       string
	}{
		{
			name:       "replaces spaces with underscores",
			commonName: "My Test Root CA",
			want:       "My_Test_Root_CA_20260720_045357",
		},
		{
			name:       "handles single word common name",
			commonName: "RootCA",
			want:       "RootCA_20260720_045357",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatCRLName(tt.commonName, now)
			if got != tt.want {
				t.Errorf("formatCRLName() = %v, want %v", got, tt.want)
			}
		})
	}
}
