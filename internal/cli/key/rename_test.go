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

package key

import (
	"testing"

	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestRenameCmd_Run(t *testing.T) {
	key1, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "rename-key-original",
		Algorithm:     "ed25519",
		PrivateKeyPem: "priv-1",
		PublicKeyPem:  "pub-1",
	})
	if err != nil {
		t.Fatalf("failed to seed key1: %v", err)
	}

	_, err = testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "rename-key-taken",
		Algorithm:     "ed25519",
		PrivateKeyPem: "priv-2",
		PublicKeyPem:  "pub-2",
	})
	if err != nil {
		t.Fatalf("failed to seed key2: %v", err)
	}

	tests := []struct {
		name        string
		cmd         RenameCmd
		wantErr     bool
		checkNewKey bool
	}{
		{
			name: "rename existing key successfully",
			cmd: RenameCmd{
				ID:   key1.ID,
				Name: "rename-key-updated",
			},
			wantErr:     false,
			checkNewKey: true,
		},
		{
			name: "rename with empty name returns error",
			cmd: RenameCmd{
				ID:   key1.ID,
				Name: "   ",
			},
			wantErr: true,
		},
		{
			name: "rename to duplicate key name returns error",
			cmd: RenameCmd{
				ID:   key1.ID,
				Name: "rename-key-taken",
			},
			wantErr: true,
		},
		{
			name: "rename non-existent key returns error",
			cmd: RenameCmd{
				ID:   999999,
				Name: "does-not-matter",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RenameCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkNewKey {
				updated, err := testQuerier.GetKeyByID(testCtx, key1.ID)
				if err != nil {
					t.Fatalf("failed to fetch updated key: %v", err)
				}
				if updated.Name != tt.cmd.Name {
					t.Fatalf("updated key name = %s, want %s", updated.Name, tt.cmd.Name)
				}
			}
		})
	}
}
