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
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestVerifyCmd_Run(t *testing.T) {
	// Seed root key
	rootKp, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootPrivPem, rootPubPem, _ := crypto.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)

	dbRootKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "verify-root-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(rootPrivPem),
		PublicKeyPem:  string(rootPubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed root key: %v", err)
	}

	// Create Root CA Cert
	rootSKID := []byte("verify-root-skid-1234")
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(8001),
		Subject:               pkix.Name{CommonName: "Verify Root CA"},
		Issuer:                pkix.Name{CommonName: "Verify Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          rootSKID,
		AuthorityKeyId:        rootSKID,
	}
	derRoot, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKp.PublicKey, rootKp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	pemRoot, _ := crypto.EncodeToPem(derRoot, "CERTIFICATE")

	dbRootCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   "8001",
		CommonName:     "Verify Root CA",
		Type:           "CA",
		KeyID:          dbRootKey.ID,
		Skid:           hex.EncodeToString(rootSKID),
		Akid:           hex.EncodeToString(rootSKID),
		Status:         "ACTIVE",
		NotBefore:      rootTmpl.NotBefore,
		NotAfter:       rootTmpl.NotAfter,
		CertificatePem: string(pemRoot),
	})
	if err != nil {
		t.Fatalf("failed to seed root cert: %v", err)
	}

	// Create Leaf Cert signed by Root CA
	leafKp, _ := pki.GetKey(pki.ED25519)
	leafPrivPem, leafPubPem, _ := crypto.ReturnPrivPubPem(leafKp.PrivateKey, leafKp.PublicKey)
	dbLeafKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "verify-leaf-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(leafPrivPem),
		PublicKeyPem:  string(leafPubPem),
	})

	leafSKID := []byte("verify-leaf-skid-1234")
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(8002),
		Subject:        pkix.Name{CommonName: "Verify Leaf Cert"},
		Issuer:         pkix.Name{CommonName: "Verify Root CA"},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		SubjectKeyId:   leafSKID,
		AuthorityKeyId: rootSKID,
	}
	derLeaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, leafKp.PublicKey, rootKp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	pemLeaf, _ := crypto.EncodeToPem(derLeaf, "CERTIFICATE")

	dbLeafCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   "8002",
		CommonName:     "Verify Leaf Cert",
		Type:           "LEAF",
		KeyID:          dbLeafKey.ID,
		Skid:           hex.EncodeToString(leafSKID),
		Akid:           hex.EncodeToString(rootSKID),
		Status:         "ACTIVE",
		NotBefore:      leafTmpl.NotBefore,
		NotAfter:       leafTmpl.NotAfter,
		CertificatePem: string(pemLeaf),
	})
	if err != nil {
		t.Fatalf("failed to seed leaf cert: %v", err)
	}

	tests := []struct {
		name    string
		cmd     VerifyCmd
		wantErr bool
	}{
		{
			name: "verify valid leaf cert signed by root CA",
			cmd: VerifyCmd{
				ID: dbLeafCert.ID,
			},
			wantErr: false,
		},
		{
			name: "verify root CA itself",
			cmd: VerifyCmd{
				ID: dbRootCert.ID,
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
				t.Fatalf("VerifyCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
