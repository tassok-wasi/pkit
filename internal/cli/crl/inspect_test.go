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
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestInspectCmd_Run(t *testing.T) {
	kp, _ := pki.GetKey(pki.ED25519)
	privPem, pubPem, _ := crypto.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "crl-inspect-issuer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7201),
		Subject:               pkix.Name{CommonName: "CRL Inspect CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	parsedIssuer, _ := x509.ParseCertificate(derIssuer)
	issuerPem, err := crypto.EncodeToPem(derIssuer, "CERTIFICATE")
	if err != nil {
		t.Error(err)
	}
	issuerCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   fmt.Sprintf("%x", parsedIssuer.SerialNumber),
		CommonName:     parsedIssuer.Subject.CommonName,
		Type:           string(pki.TypeRootCA),
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
		Number:     big.NewInt(10),
		ThisUpdate: now.Add(-1 * time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   big.NewInt(100),
				RevocationTime: now,
			},
		},
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTmpl, parsedIssuer, kp.PrivateKey.(stdcrypto.Signer))
	crlPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	dbCRL, err := testQuerier.CreateCRL(testCtx, sqlc.CreateCRLParams{
		Name:       "Inspect_CRL_" + t.Name(),
		CrlNumber:  10,
		IssuerID:   issuerCert.ID,
		ThisUpdate: crlTmpl.ThisUpdate,
		NextUpdate: crlTmpl.NextUpdate,
		CrlPem:     string(crlPEMBlock),
	})
	if err != nil {
		t.Fatalf("failed to seed CRL for inspection: %v", err)
	}

	tests := []struct {
		name    string
		cmd     InspectCmd
		wantErr bool
	}{
		{
			name:    "inspect existing CRL",
			cmd:     InspectCmd{ID: dbCRL.ID},
			wantErr: false,
		},
		{
			name:    "non-existent CRL returns error",
			cmd:     InspectCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InspectCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
