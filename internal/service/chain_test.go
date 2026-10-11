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

package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
	"github.com/tassok-wasi/pkit/testutil"
	"github.com/zalando/go-keyring"
)

var (
	testCtx     context.Context
	testDB      *sql.DB
	testQuerier sqlc.Querier
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	if err := crypto.InitMasterKey(); err != nil {
		panic(err)
	}

	var err error
	testDB, err = testutil.InitializeTestDB("service-chain-test", store.Schema)
	if err != nil {
		panic(err)
	}

	testCtx = context.Background()
	testQuerier = sqlc.New(testDB)

	code := m.Run()
	if err := testDB.Close(); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func TestBuildChain(t *testing.T) {
	svc := New(testDB, testQuerier)

	// Root CA Key & Cert
	rootKp, _ := pki.GetKey(pki.ED25519)
	rootPrivPem, rootPubPem, _ := crypto.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)
	dbRootKey, _ := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
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
	pemRoot, _ := crypto.EncodeToPem(derRoot, "CERTIFICATE")
	parsedRoot, _ := x509.ParseCertificate(derRoot)

	_, _ = testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
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
	leafKp, _ := pki.GetKey(pki.ED25519)
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
			chain, err := svc.buildChain(testCtx, tt.current)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildChain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(chain) != tt.wantChainLen {
				t.Errorf("buildChain() len = %v, want %v", len(chain), tt.wantChainLen)
			}
		})
	}
}
