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

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestExportCmd_Run(t *testing.T) {
	// 1. Seed a test key into the shared SQLite DB
	keyPair, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	privPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key pair: %v", err)
	}

	createdKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
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
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExportCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.checkFiles != nil {
				tt.checkFiles(t, tt.cmd.Path)
			}
		})
	}
}

func TestResolveKeyDestinationPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputPath   string
		keyName     string
		ext         string
		wantPriv    string
		wantPub     string
		expectError bool
	}{
		{
			name:        "empty input path",
			inputPath:   "",
			keyName:     "My Key",
			ext:         ".pem",
			wantPriv:    "my_key_private_key.pem",
			wantPub:     "my_key_public_key.pem",
			expectError: false,
		},
		{
			name:        "input path is directory",
			inputPath:   "/tmp",
			keyName:     "Test Key",
			ext:         ".der",
			wantPriv:    "/tmp/test_key_private_key.der",
			wantPub:     "/tmp/test_key_public_key.der",
			expectError: false,
		},
		{
			name:        "input path is file",
			inputPath:   "/tmp/output",
			keyName:     "My Key",
			ext:         ".pem",
			wantPriv:    "/tmp/output/my_key_private_key.pem",
			wantPub:     "/tmp/output/my_key_public_key.pem",
			expectError: false,
		},
		{
			name:        "input path is file with extension",
			inputPath:   "/tmp/output.txt",
			keyName:     "My Key",
			ext:         ".pem",
			wantPriv:    "/tmp/output_private_key.pem",
			wantPub:     "/tmp/output_public_key.pem",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotPriv, gotPub, err := resolveKeyDestinationPaths(tt.inputPath, tt.keyName, tt.ext)

			if (err != nil) != tt.expectError {
				t.Errorf("resolveKeyDestinationPaths() error = %v, expectError = %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				if gotPriv != tt.wantPriv {
					t.Errorf("resolveKeyDestinationPaths() gotPriv = %v, want %v", gotPriv, tt.wantPriv)
				}

				if gotPub != tt.wantPub {
					t.Errorf("resolveKeyDestinationPaths() gotPub = %v, want %v", gotPub, tt.wantPub)
				}
			}
		})
	}
}
