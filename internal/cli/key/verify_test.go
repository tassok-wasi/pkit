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

package key

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

func TestVerifyCmd_Run(t *testing.T) {
	// Generate matching KeyPair + Certificate
	keyPair, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, err := crypto.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key pair: %v", err)
	}

	keyName := "verify-test-key"
	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          keyName,
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to insert key into DB: %v", err)
	}

	// Create self-signed x509 Cert using generated key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "Verify Test Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPem, err := crypto.EncodeToPem(certBytes, "CERTIFICATE")
	if err != nil {
		t.Fatalf("failed to encode cert PEM: %v", err)
	}

	dbCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   "1001",
		CommonName:     "Verify Test Cert",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "skid-123",
		Akid:           "akid-123",
		Status:         "ACTIVE",
		NotBefore:      template.NotBefore,
		NotAfter:       template.NotAfter,
		CertificatePem: string(certPem),
	})
	if err != nil {
		t.Fatalf("failed to insert cert into DB: %v", err)
	}

	tests := []struct {
		name    string
		cmd     VerifyCmd
		wantErr bool
	}{
		{
			name: "verify key and certificate match",
			cmd: VerifyCmd{
				ID: int(dbCert.ID),
			},
			wantErr: false,
		},
		{
			name: "verify non-existent cert ID",
			cmd: VerifyCmd{
				ID: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
