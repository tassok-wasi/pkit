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

package csr

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestExportCmd_Run(t *testing.T) {
	kp, _ := pki.GetKey(pki.ED25519)
	privKeyPem, pubKeyPem, err := crypto.MarshalKeys(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	keys, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "inspect.example.com",
		Algorithm:     string(pki.ED25519),
		PrivateKeyPem: string(privKeyPem),
		PublicKeyPem:  string(pubKeyPem),
	})
	if err != nil {
		t.Error(err)
	}

	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "export.example.com"},
	}
	derCSR, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, kp.PrivateKey)
	pemCSR, _ := crypto.EncodeToPem(derCSR, "CERTIFICATE REQUEST")

	dbCSR, err := testQuerier.CreateCSR(testCtx, sqlc.CreateCSRParams{
		CommonName: "export.example.com",
		CsrPem:     string(pemCSR),
		Status:     "PENDING",
		KeyID:      keys.ID,
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		cmd        ExportCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetDir string)
	}{
		{
			name: "export CSR in PEM format",
			cmd: ExportCmd{
				ID:     dbCSR.ID,
				Path:   filepath.Join(tmpDir, "csr_export_pem"),
				Format: "pem",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				expectedFile := filepath.Join(targetDir, "export.example.com_csr.pem")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported CSR file at %s", expectedFile)
				}
			},
		},
		{
			name: "export CSR in DER format",
			cmd: ExportCmd{
				ID:     dbCSR.ID,
				Path:   filepath.Join(tmpDir, "csr_export_der"),
				Format: "der",
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				expectedFile := filepath.Join(targetDir, "export.example.com_csr.der")
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("expected exported DER CSR file at %s", expectedFile)
				}
			},
		},
		{
			name: "unsupported format returns error",
			cmd: ExportCmd{
				ID:     dbCSR.ID,
				Format: "unsupported_format",
			},
			wantErr: true,
		},
		{
			name: "non-existent CSR ID returns error",
			cmd: ExportCmd{
				ID:     999999,
				Format: "pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExportCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}
