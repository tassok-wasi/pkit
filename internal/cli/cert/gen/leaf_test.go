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

package gen

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestLeafCmd_Run(t *testing.T) {
	// Seed Issuer CA Key & Cert
	issuerKp, _ := pki.GetKey(pki.ED25519)
	issuerPrivPem, issuerPubPem, _ := crypto.ReturnPrivPubPem(issuerKp.PrivateKey, issuerKp.PublicKey)
	dbIssuerKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "leaf-issuer-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(issuerPrivPem),
		PublicKeyPem:  string(issuerPubPem),
	})

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9101),
		Subject:               pkix.Name{CommonName: "Leaf Signing Issuer CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, issuerKp.PublicKey, issuerKp.PrivateKey)
	pemIssuer, _ := crypto.EncodeToPem(derIssuer, "CERTIFICATE")

	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   "9101",
		CommonName:     "Leaf Signing Issuer CA",
		Type:           string(pki.TypeRootCA),
		KeyID:          dbIssuerKey.ID,
		Skid:           "leaf-issuer-skid",
		Akid:           "leaf-issuer-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:      issuerTmpl.NotBefore,
		NotAfter:       issuerTmpl.NotAfter,
		CertificatePem: string(pemIssuer),
	})
	if err != nil {
		t.Fatalf("failed to seed leaf issuer cert: %v", err)
	}

	// Seed Leaf Key
	leafKp, _ := pki.GetKey(pki.ED25519)
	leafPrivPem, leafPubPem, _ := crypto.ReturnPrivPubPem(leafKp.PrivateKey, leafKp.PublicKey)
	dbLeafKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "leaf-target-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(leafPrivPem),
		PublicKeyPem:  string(leafPubPem),
	})

	tests := []struct {
		name    string
		cmd     LeafCmd
		wantErr bool
	}{
		{
			name: "generate valid Leaf certificate with SANs",
			cmd: LeafCmd{
				CommonName:   "app.example.com",
				KeyID:        dbLeafKey.ID,
				IssuerID:     dbIssuerCert.ID,
				TTL:          "720h",
				DNSNames:     []string{"app.example.com", "api.example.com"},
				IPAddresses:  []string{"192.168.1.1"},
				KeyUsages:    []string{"digital-signature", "key-encipherment"},
				ExtKeyUsages: []string{"server-auth", "client-auth"},
			},
			wantErr: false,
		},
		{
			name: "invalid IP address format returns error",
			cmd: LeafCmd{
				CommonName:  "badip.example.com",
				KeyID:       dbLeafKey.ID,
				IssuerID:    dbIssuerCert.ID,
				TTL:         "720h",
				IPAddresses: []string{"invalid_ip_address"},
			},
			wantErr: true,
		},
		{
			name: "non-existent issuer ID returns error",
			cmd: LeafCmd{
				CommonName: "noissuer.example.com",
				KeyID:      dbLeafKey.ID,
				IssuerID:   999999,
				TTL:        "720h",
			},
			wantErr: true,
		},
		{
			name: "zero TTL returns error",
			cmd: LeafCmd{
				CommonName: "zero-ttl.example.com",
				KeyID:      dbLeafKey.ID,
				IssuerID:   dbIssuerCert.ID,
				TTL:        "0h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LeafCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
