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

package cert

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

func TestRotateCmd_Run(t *testing.T) {
	// Seed Key 1
	kp1, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key 1: %v", err)
	}
	privPem1, pubPem1, _ := utils.ReturnPrivPubPem(kp1.PrivateKey, kp1.PublicKey)

	dbKey1, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "rotate-key-1",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem1),
		PublicKeyPem:  string(pubPem1),
	})
	if err != nil {
		t.Fatalf("failed to seed key 1: %v", err)
	}

	// Seed Key 2 (For rotation)
	kp2, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key 2: %v", err)
	}
	privPem2, pubPem2, _ := utils.ReturnPrivPubPem(kp2.PrivateKey, kp2.PublicKey)

	dbKey2, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "rotate-key-2",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem2),
		PublicKeyPem:  string(pubPem2),
	})
	if err != nil {
		t.Fatalf("failed to seed key 2: %v", err)
	}

	// Create Root CA Cert
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(6001),
		Subject:               pkix.Name{CommonName: "Rotate Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp1.PublicKey, kp1.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	pem, _ := utils.EncodeToPem(der, "CERTIFICATE")

	dbRootCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "6001",
		CommonName:     "Rotate Root CA",
		Type:           "CA",
		KeyID:          dbKey1.ID,
		Skid:           "rotate-skid",
		Akid:           "rotate-akid",
		Status:         "ACTIVE",
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pem),
	})
	if err != nil {
		t.Fatalf("failed to seed root cert: %v", err)
	}

	tests := []struct {
		name    string
		cmd     RotateCmd
		wantErr bool
	}{
		{
			name: "rotate self-signed Root CA cert with new key pair",
			cmd: RotateCmd{
				ID:    dbRootCert.ID,
				KeyID: dbKey2.ID,
			},
			wantErr: false,
		},
		{
			name: "rotate non-existent cert ID",
			cmd: RotateCmd{
				ID:    999999,
				KeyID: dbKey2.ID,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testDB, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RotateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
