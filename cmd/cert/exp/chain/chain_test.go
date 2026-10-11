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

package chain

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestChainCmd_Run(t *testing.T) {
	// Seed Parent Root CA
	rootKp, _ := domain.GetKey(domain.ED25519)
	rootPrivPem, rootPubPem, _ := utils.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)
	dbRootKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "exp-chain-root-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(rootPrivPem),
		PublicKeyPem:  string(rootPubPem),
	})

	rootSkid := []byte("exp-chain-root-skid")
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9401),
		Subject:               pkix.Name{CommonName: "Exp Chain Root CA"},
		Issuer:                pkix.Name{CommonName: "Exp Chain Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          rootSkid,
		AuthorityKeyId:        rootSkid,
	}
	derRoot, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKp.PublicKey, rootKp.PrivateKey)
	pemRoot, _ := utils.EncodeToPem(derRoot, "CERTIFICATE")

	_, _ = testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "9401",
		CommonName:     "Exp Chain Root CA",
		Type:           "CA",
		KeyID:          dbRootKey.ID,
		Skid:           hex.EncodeToString(rootSkid),
		Akid:           hex.EncodeToString(rootSkid),
		Status:         "ACTIVE",
		NotBefore:      rootTmpl.NotBefore,
		NotAfter:       rootTmpl.NotAfter,
		CertificatePem: string(pemRoot),
	})

	// Seed Leaf Certificate
	leafKp, _ := domain.GetKey(domain.ED25519)
	leafPrivPem, leafPubPem, _ := utils.ReturnPrivPubPem(leafKp.PrivateKey, leafKp.PublicKey)
	dbLeafKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "exp-chain-leaf-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(leafPrivPem),
		PublicKeyPem:  string(leafPubPem),
	})

	leafSkid := []byte("exp-chain-leaf-skid")
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9402),
		Subject:               pkix.Name{CommonName: "Exp Chain Leaf Cert"},
		Issuer:                pkix.Name{CommonName: "Exp Chain Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		SubjectKeyId:          leafSkid,
		AuthorityKeyId:        rootSkid,
		BasicConstraintsValid: true,
	}
	derLeaf, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, leafKp.PublicKey, rootKp.PrivateKey)
	pemLeaf, _ := utils.EncodeToPem(derLeaf, "CERTIFICATE")

	dbLeafCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "9402",
		CommonName:     "Exp Chain Leaf Cert",
		Type:           "LEAF",
		KeyID:          dbLeafKey.ID,
		Skid:           hex.EncodeToString(leafSkid),
		Akid:           hex.EncodeToString(rootSkid),
		Status:         "ACTIVE",
		NotBefore:      leafTmpl.NotBefore,
		NotAfter:       leafTmpl.NotAfter,
		CertificatePem: string(pemLeaf),
	})
	if err != nil {
		t.Fatalf("failed to seed leaf cert: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		cmd        ChainCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetDir string)
	}{
		{
			name: "export chain in PEM format",
			cmd: ChainCmd{
				ID:     dbLeafCert.ID,
				Path:   filepath.Join(tmpDir, "chain_pem"),
				Format: "pem",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				path := filepath.Join(targetDir, "exp_chain_leaf_cert_chain.pem")
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected chain file at %s", path)
				}
			},
		},
		{
			name: "export chain in PKCS7 format",
			cmd: ChainCmd{
				ID:     dbLeafCert.ID,
				Path:   filepath.Join(tmpDir, "chain_p7b"),
				Format: "pkcs7",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				path := filepath.Join(targetDir, "exp_chain_leaf_cert_chain.p7b")
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected PKCS7 chain file at %s", path)
				}
			},
		},
		{
			name: "non-existent cert ID returns error",
			cmd: ChainCmd{
				ID:     999999,
				Format: "pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ChainCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}
