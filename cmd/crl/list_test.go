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
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestListCmd_Run(t *testing.T) {
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "crl-list-issuer-key-" + t.Name(),
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(8001),
		Subject:               pkix.Name{CommonName: "CRL List Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	pemBytes, _ := utils.EncodeToPem(der, "CERTIFICATE")

	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "8001",
		CommonName:     "CRL List Issuer CA",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "crl-list-skid",
		Akid:           "crl-list-akid",
		Status:         "ACTIVE",
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pemBytes),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}

	issuerID := dbIssuerCert.ID
	now := time.Now()

	_, err = testQuerier.CreateCRL(testCtx, base.CreateCRLParams{
		Name:       "List_CRL_1_" + t.Name(),
		CrlNumber:  1,
		IssuerID:   issuerID,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		CrlPem:     "-----BEGIN X509 CRL-----\nPEM_1\n-----END X509 CRL-----",
	})
	if err != nil {
		t.Fatalf("failed to seed CRL: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ListCmd
		wantErr bool
	}{
		{
			name:    "list all CRLs for issuer without limit or offset",
			cmd:     ListCmd{IssuerID: issuerID},
			wantErr: false,
		},
		{
			name:    "list CRLs with pagination limit and offset",
			cmd:     ListCmd{IssuerID: issuerID, Limit: 10, Offset: 0},
			wantErr: false,
		},
		{
			name:    "list CRLs for issuer with no entries returns no error",
			cmd:     ListCmd{IssuerID: 999999},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
