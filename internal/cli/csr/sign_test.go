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

package csr

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestSignCmd_Run(t *testing.T) {
	// 1. Seed Issuer CA Key and Certificate
	issuerKp, _ := pki.GetKey(pki.ED25519)
	issuerPrivPem, issuerPubPem, _ := crypto.ReturnPrivPubPem(issuerKp.PrivateKey, issuerKp.PublicKey)

	dbIssuerKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "csr-signer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(issuerPrivPem),
		PublicKeyPem:  string(issuerPubPem),
	})

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(6001),
		Subject:               pkix.Name{CommonName: "CSR Signer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, issuerKp.PublicKey, issuerKp.PrivateKey)
	pemIssuer, _ := crypto.EncodeToPem(derIssuer, "CERTIFICATE")

	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   "6001",
		CommonName:     "CSR Signer CA",
		Type:           "CA",
		KeyID:          dbIssuerKey.ID,
		Skid:           "signer-skid",
		Akid:           "signer-akid",
		Status:         "ACTIVE",
		NotBefore:      issuerTmpl.NotBefore,
		NotAfter:       issuerTmpl.NotAfter,
		CertificatePem: string(pemIssuer),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}

	// 2. Seed Target CSR
	targetKp, _ := pki.GetKey(pki.ED25519)
	privKeyPem, pubKeyPem, err := crypto.MarshalKeys(targetKp.PrivateKey, targetKp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "sign.example.com" + t.Name(),
		Algorithm:     string(pki.ED25519),
		PrivateKeyPem: string(privKeyPem),
		PublicKeyPem:  string(pubKeyPem),
	})
	if err != nil {
		t.Error(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "target.example.com"},
	}
	derCSR, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, targetKp.PrivateKey)
	pemCSR, _ := crypto.EncodeToPem(derCSR, "CERTIFICATE REQUEST")

	dbCSR, err := testQuerier.CreateCSR(testCtx, sqlc.CreateCSRParams{
		CommonName: "target.example.com",
		CsrPem:     string(pemCSR),
		Status:     "PENDING",
		KeyID:      dbKey.ID,
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tests := []struct {
		name    string
		cmd     SignCmd
		wantErr bool
	}{
		{
			name: "successfully sign CSR to generate leaf certificate",
			cmd: SignCmd{
				ID:           dbCSR.ID,
				IssuerID:     dbIssuerCert.ID,
				Type:         "LEAF",
				TTL:          "720h",
				KeyUsages:    []string{"digital_signature"},
				ExtKeyUsages: []string{"server_auth"},
			},
			wantErr: false,
		},
		{
			name: "invalid TTL string returns error",
			cmd: SignCmd{
				ID:       dbCSR.ID,
				IssuerID: dbIssuerCert.ID,
				TTL:      "invalid_ttl",
			},
			wantErr: true,
		},
		{
			name: "non-existent CSR ID returns error",
			cmd: SignCmd{
				ID:       999999,
				IssuerID: dbIssuerCert.ID,
				TTL:      "720h",
			},
			wantErr: true,
		},
		{
			name: "non-existent issuer ID returns error",
			cmd: SignCmd{
				ID:       dbCSR.ID,
				IssuerID: 999999,
				TTL:      "720h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SignCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
