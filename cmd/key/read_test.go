// Copyright 2026 Tassok Imam Wasi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package key

import (
	"testing"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestReadCmd_Run(t *testing.T) {
	// Seed test key
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, err := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "read-cmd-test-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ReadCmd
		wantErr bool
	}{
		{
			name: "read existing valid key pair",
			cmd: ReadCmd{
				ID: int(dbKey.ID),
			},
			wantErr: false,
		},
		{
			name: "read non-existent key ID",
			cmd: ReadCmd{
				ID: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
