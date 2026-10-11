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
	"os"
	"path/filepath"
	"testing"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestExportCmd_Run(t *testing.T) {
	// 1. Seed a test key into the shared SQLite DB
	keyPair, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	privPem, pubPem, err := crypto.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key pair: %v", err)
	}

	createdKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "Export Test Key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed test key: %v", err)
	}

	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		cmd        ExportCmd
		wantErr    bool
		checkFiles func(t *testing.T, targetDir string)
	}{
		{
			name: "export PEM format success",
			cmd: ExportCmd{
				ID:     createdKey.ID,
				Path:   filepath.Join(tmpDir, "pem_export"),
				Format: "pem",
				Blob:   false,
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				priv := filepath.Join(targetDir, "export_test_key_private_key.pem")
				pub := filepath.Join(targetDir, "export_test_key_public_key.pem")
				if _, err := os.Stat(priv); os.IsNotExist(err) {
					t.Errorf("expected private key file at %s", priv)
				}
				if _, err := os.Stat(pub); os.IsNotExist(err) {
					t.Errorf("expected public key file at %s", pub)
				}
			},
		},
		{
			name: "export DER format success",
			cmd: ExportCmd{
				ID:     createdKey.ID,
				Path:   filepath.Join(tmpDir, "der_export"),
				Format: "der",
				Blob:   false,
			},
			wantErr: false,
			checkFiles: func(t *testing.T, targetDir string) {
				priv := filepath.Join(targetDir, "export_test_key_private_key.der")
				pub := filepath.Join(targetDir, "export_test_key_public_key.der")
				if _, err := os.Stat(priv); os.IsNotExist(err) {
					t.Errorf("expected private key file at %s", priv)
				}
				if _, err := os.Stat(pub); os.IsNotExist(err) {
					t.Errorf("expected public key file at %s", pub)
				}
			},
		},
		{
			name: "invalid key ID",
			cmd: ExportCmd{
				ID:     999999,
				Format: "pem",
			},
			wantErr: true,
		},
		{
			name: "unsupported format",
			cmd: ExportCmd{
				ID:     createdKey.ID,
				Format: "invalid_format",
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
