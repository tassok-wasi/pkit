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

package helper

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestGetCertificateChain(t *testing.T) {
	// Root CA Key & Cert
	rootKp, _ := domain.GetKey(domain.ED25519)
	rootPrivPem, rootPubPem, _ := utils.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)
	dbRootKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "chain-root-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(rootPrivPem),
		PublicKeyPem:  string(rootPubPem),
	})

	rootSkid := []byte("root-skid-12345")
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Root CA Helper"},
		Issuer:                pkix.Name{CommonName: "Root CA Helper"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          rootSkid,
		AuthorityKeyId:        rootSkid,
	}
	derRoot, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKp.PublicKey, rootKp.PrivateKey)
	pemRoot, _ := utils.EncodeToPem(derRoot, "CERTIFICATE")
	parsedRoot, _ := x509.ParseCertificate(derRoot)

	_, _ = testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "1001",
		CommonName:     "Root CA Helper",
		Type:           "CA",
		KeyID:          dbRootKey.ID,
		Skid:           hex.EncodeToString(rootSkid),
		Akid:           hex.EncodeToString(rootSkid),
		Status:         "ACTIVE",
		NotBefore:      rootTmpl.NotBefore,
		NotAfter:       rootTmpl.NotAfter,
		CertificatePem: string(pemRoot),
	})

	// Leaf Cert signed by Root
	leafKp, _ := domain.GetKey(domain.ED25519)
	leafSkid := []byte("leaf-skid-67890")
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "Leaf Cert Helper"},
		Issuer:                pkix.Name{CommonName: "Root CA Helper"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          leafSkid,
		AuthorityKeyId:        rootSkid,
	}
	derLeaf, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, leafKp.PublicKey, rootKp.PrivateKey)
	parsedLeaf, _ := x509.ParseCertificate(derLeaf)

	// Invalid Cert lacking AKID
	noAkidTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1003),
		Subject:               pkix.Name{CommonName: "No AKID Cert"},
		Issuer:                pkix.Name{CommonName: "Different Issuer"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	derNoAkid, _ := x509.CreateCertificate(rand.Reader, noAkidTmpl, noAkidTmpl, leafKp.PublicKey, leafKp.PrivateKey)
	parsedNoAkid, _ := x509.ParseCertificate(derNoAkid)

	tests := []struct {
		name         string
		current      *x509.Certificate
		wantChainLen int
		wantErr      bool
	}{
		{
			name:         "valid leaf cert resolves root parent in chain",
			current:      parsedLeaf,
			wantChainLen: 1,
			wantErr:      false,
		},
		{
			name:         "providing root cert directly returns error",
			current:      parsedRoot,
			wantChainLen: 0,
			wantErr:      true,
		},
		{
			name:         "cert without AKID returns error",
			current:      parsedNoAkid,
			wantChainLen: 0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, err := GetCertificateChain(testCtx, testQuerier, tt.current)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetCertificateChain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(chain) != tt.wantChainLen {
				t.Errorf("GetCertificateChain() len = %v, want %v", len(chain), tt.wantChainLen)
			}
		})
	}
}
