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
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestVerifyCmd_Run(t *testing.T) {
	// Seed Issuer Key and Certificate
	kp, _ := domain.GetKey(domain.ED25519)
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "crl-verify-issuer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7101),
		Subject:               pkix.Name{CommonName: "CRL Verify Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	pemIssuer, _ := utils.EncodeToPem(derIssuer, "CERTIFICATE")
	parsedIssuer, _ := x509.ParseCertificate(derIssuer)

	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "7101",
		CommonName:     "CRL Verify Issuer CA",
		Type:           string(domain.TypeRootCA),
		KeyID:          dbKey.ID,
		Skid:           "crl-verify-skid",
		Akid:           "crl-verify-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pemIssuer),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}

	// Generate and seed signed CRL
	now := time.Now()
	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-1 * time.Hour),
		NextUpdate: now.Add(168 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTmpl, parsedIssuer, kp.PrivateKey.(crypto.Signer))
	crlPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	dbCRL, err := testQuerier.CreateCRL(testCtx, base.CreateCRLParams{
		Name:       "Valid_CRL_" + t.Name(),
		CrlNumber:  1,
		IssuerID:   dbIssuerCert.ID,
		ThisUpdate: crlTmpl.ThisUpdate,
		NextUpdate: crlTmpl.NextUpdate,
		CrlPem:     string(crlPEMBlock),
	})
	if err != nil {
		t.Fatalf("failed to seed CRL: %v", err)
	}

	tests := []struct {
		name    string
		cmd     VerifyCmd
		wantErr bool
	}{
		{
			name:    "verify valid CRL signed by issuer",
			cmd:     VerifyCmd{ID: dbCRL.ID},
			wantErr: false,
		},
		{
			name:    "non-existent CRL ID returns error",
			cmd:     VerifyCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
