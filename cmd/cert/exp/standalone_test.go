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

package exp

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestLeafCmd_Run(t *testing.T) {
	// Seed Key Pair and Leaf Certificate
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "exp-leaf-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9301),
		Subject:      pkix.Name{CommonName: "Export Leaf Test Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	pem, _ := utils.EncodeToPem(der, "CERTIFICATE")

	dbCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "9301",
		CommonName:     "Export Leaf Test Cert",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "exp-leaf-skid",
		Akid:           "exp-leaf-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: false},
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pem),
	})
	if err != nil {
		t.Fatalf("failed to seed cert: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		cmd        StandaloneCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetPath string)
	}{
		{
			name: "export leaf cert in PEM format",
			cmd: StandaloneCmd{
				ID:     dbCert.ID,
				Path:   filepath.Join(tmpDir, "leaf_export_pem"),
				Format: "pem",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetPath string) {
				expectedFile := filepath.Join(targetPath, "export_leaf_test_cert.pem")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported certificate at %s", expectedFile)
				}
			},
		},
		{
			name: "export leaf cert in DER format",
			cmd: StandaloneCmd{
				ID:     dbCert.ID,
				Path:   filepath.Join(tmpDir, "leaf_export_der"),
				Format: "der",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetPath string) {
				expectedFile := filepath.Join(targetPath, "export_leaf_test_cert.der")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported DER certificate at %s", expectedFile)
				}
			},
		},
		{
			name: "unsupported export format returns error",
			cmd: StandaloneCmd{
				ID:     dbCert.ID,
				Format: "unsupported_fmt",
			},
			wantErr: true,
		},
		{
			name: "non-existent cert ID returns error",
			cmd: StandaloneCmd{
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
				t.Fatalf("LeafCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}
