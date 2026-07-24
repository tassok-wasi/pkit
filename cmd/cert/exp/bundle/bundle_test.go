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

package bundle

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

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestBundleCmd_Run(t *testing.T) {
	// Seed Parent Root CA
	rootKp, _ := domain.GetKey(domain.ED25519)
	rootPrivPem, rootPubPem, _ := utils.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)
	dbRootKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "exp-bundle-root-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(rootPrivPem),
		PublicKeyPem:  string(rootPubPem),
	})

	rootSkid := []byte("exp-bundle-root-skid")
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9501),
		Subject:               pkix.Name{CommonName: "Exp Bundle Root CA"},
		Issuer:                pkix.Name{CommonName: "Exp Bundle Root CA"},
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
		SerialNumber:   "9501",
		CommonName:     "Exp Bundle Root CA",
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
		Name:          "exp-bundle-leaf-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(leafPrivPem),
		PublicKeyPem:  string(leafPubPem),
	})

	leafSkid := []byte("exp-bundle-leaf-skid")
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9502),
		Subject:               pkix.Name{CommonName: "Exp Bundle Leaf Cert"},
		Issuer:                pkix.Name{CommonName: "Exp Bundle Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		SubjectKeyId:          leafSkid,
		AuthorityKeyId:        rootSkid,
		BasicConstraintsValid: true,
	}
	derLeaf, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, leafKp.PublicKey, leafKp.PrivateKey)
	pemLeaf, _ := utils.EncodeToPem(derLeaf, "CERTIFICATE")

	dbLeafCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "9502",
		CommonName:     "Exp Bundle Leaf Cert",
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
		cmd        BundleCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetDir string)
	}{
		{
			name: "export bundle in PEM format",
			cmd: BundleCmd{
				ID:     dbLeafCert.ID,
				Path:   filepath.Join(tmpDir, "bundle_pem"),
				Format: "pem",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				path := filepath.Join(targetDir, "exp_bundle_leaf_cert_bundle.pem")
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected PEM bundle file at %s", path)
				}
			},
		},
		{
			name: "export bundle in PKCS12 format",
			cmd: BundleCmd{
				ID:         dbLeafCert.ID,
				Path:       filepath.Join(tmpDir, "bundle_p12"),
				Format:     "pkcs12",
				PassPhrase: "secretpassword",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				path := filepath.Join(targetDir, "exp_bundle_leaf_cert_bundle.p12")
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("expected PKCS12 bundle file at %s", path)
				}
			},
		},
		{
			name: "non-existent cert ID returns error",
			cmd: BundleCmd{
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
				t.Fatalf("BundleCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}
