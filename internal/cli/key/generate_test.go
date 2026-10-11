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
	"testing"
)

func TestGenerateCmd_Run(t *testing.T) {
	tests := []struct {
		name    string
		cmd     GenerateCmd
		wantErr bool
	}{
		{
			name: "generate ed25519 key",
			cmd: GenerateCmd{
				KeyType: "ed25519",
				Name:    "gen-test-ed25519",
			},
			wantErr: false,
		},
		{
			name: "generate ecdsa-256 key",
			cmd: GenerateCmd{
				KeyType: "ecdsa-256",
				Name:    "gen-test-ecdsa256",
			},
			wantErr: false,
		},
		{
			name: "generate rsa-2048 key",
			cmd: GenerateCmd{
				KeyType: "rsa-2048",
				Name:    "gen-test-rsa2048",
			},
			wantErr: false,
		},
		{
			name: "invalid key algorithm type",
			cmd: GenerateCmd{
				KeyType: "invalid-algo",
				Name:    "gen-test-invalid",
			},
			wantErr: true,
		},
		{
			name: "duplicate key name constraint error",
			cmd: GenerateCmd{
				KeyType: "ed25519",
				Name:    "gen-test-ed25519", // Duplicate of first test case
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				k, err := testQuerier.GetKeyByName(testCtx, tt.cmd.Name)
				if err != nil {
					t.Fatalf("expected key %s to exist in DB, got: %v", tt.cmd.Name, err)
				}
				if k.Algorithm != tt.cmd.KeyType {
					t.Errorf("expected algorithm %s, got %s", tt.cmd.KeyType, k.Algorithm)
				}
			}
		})
	}
}
