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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestExportCmd_Run(t *testing.T) {
	kp, _ := domain.GetKey(domain.ED25519)
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "crl-export-issuer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7401),
		Subject:               pkix.Name{CommonName: "CRL Export CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	parsedIssuer, _ := x509.ParseCertificate(derIssuer)
	issuerPem, err := utils.EncodeToPem(derIssuer, "CERTIFICATE")
	if err != nil {
		t.Error(err)
	}
	issuerCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   fmt.Sprintf("%x", parsedIssuer.SerialNumber),
		CommonName:     parsedIssuer.Subject.CommonName,
		Type:           string(domain.TypeRootCA),
		KeyID:          dbKey.ID,
		Skid:           hex.EncodeToString(parsedIssuer.SubjectKeyId),
		Akid:           hex.EncodeToString(parsedIssuer.AuthorityKeyId),
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: false},
		NotBefore:      parsedIssuer.NotBefore,
		NotAfter:       parsedIssuer.NotAfter,
		CertificatePem: string(issuerPem),
	})
	if err != nil {
		t.Error(err)
	}

	now := time.Now()
	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(100),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTmpl, parsedIssuer, kp.PrivateKey.(crypto.Signer))
	crlPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	dbCRL, err := testQuerier.CreateCRL(testCtx, base.CreateCRLParams{
		Name:       "Export_CRL_Test",
		CrlNumber:  100,
		IssuerID:   issuerCert.ID,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		CrlPem:     string(crlPEMBlock),
	})
	if err != nil {
		t.Fatalf("failed to seed CRL: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		cmd        ExportCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetDir string)
	}{
		{
			name: "export CRL in PEM format",
			cmd: ExportCmd{
				ID:     dbCRL.ID,
				Path:   filepath.Join(tmpDir, "crl_export_pem"),
				Format: "pem",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				expectedFile := filepath.Join(targetDir, "export_crl_test_crl.pem")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported CRL file at %s", expectedFile)
				}
			},
		},
		{
			name: "export CRL in DER format",
			cmd: ExportCmd{
				ID:     dbCRL.ID,
				Path:   filepath.Join(tmpDir, "crl_export_der"),
				Format: "der",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				expectedFile := filepath.Join(targetDir, "export_crl_test_crl.der")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported DER CRL file at %s", expectedFile)
				}
			},
		},
		{
			name: "unsupported format returns error",
			cmd: ExportCmd{
				ID:     dbCRL.ID,
				Format: "invalid_fmt",
			},
			wantErr: true,
		},
		{
			name: "non-existent CRL ID returns error",
			cmd: ExportCmd{
				ID:     999999,
				Format: "pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExportCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}
