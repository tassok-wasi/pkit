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

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestDiffCmd_Run(t *testing.T) {
	// Seed test key and certificates
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, err := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "diff-test-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	// Create Cert 1
	tmpl1 := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "Diff Cert 1"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der1, err := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create cert 1: %v", err)
	}
	pem1, _ := utils.EncodeToPem(der1, "CERTIFICATE")

	cert1, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "1001",
		CommonName:     "Diff Cert 1",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "skid1",
		Akid:           "akid1",
		Status:         "ACTIVE",
		NotBefore:      tmpl1.NotBefore,
		NotAfter:       tmpl1.NotAfter,
		CertificatePem: string(pem1),
	})
	if err != nil {
		t.Fatalf("failed to seed cert 1: %v", err)
	}

	// Create Cert 2 (Different CN)
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject:      pkix.Name{CommonName: "Diff Cert 2"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der2, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create cert 2: %v", err)
	}
	pem2, _ := utils.EncodeToPem(der2, "CERTIFICATE")

	cert2, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "1002",
		CommonName:     "Diff Cert 2",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "skid2",
		Akid:           "akid2",
		Status:         "ACTIVE",
		NotBefore:      tmpl2.NotBefore,
		NotAfter:       tmpl2.NotAfter,
		CertificatePem: string(pem2),
	})
	if err != nil {
		t.Fatalf("failed to seed cert 2: %v", err)
	}

	tests := []struct {
		name    string
		cmd     DiffCmd
		wantErr bool
	}{
		{
			name: "diff two different certificates",
			cmd: DiffCmd{
				ID1: cert1.ID,
				ID2: cert2.ID,
			},
			wantErr: false,
		},
		{
			name: "diff identical certificates (same ID)",
			cmd: DiffCmd{
				ID1: cert1.ID,
				ID2: cert1.ID,
			},
			wantErr: false,
		},
		{
			name: "non-existent ID1",
			cmd: DiffCmd{
				ID1: 999999,
				ID2: cert2.ID,
			},
			wantErr: true,
		},
		{
			name: "non-existent ID2",
			cmd: DiffCmd{
				ID1: cert1.ID,
				ID2: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DiffCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
