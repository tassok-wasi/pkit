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

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestInspectCmd_Run(t *testing.T) {
	// Seed keys for each supported type
	algos := []string{"ed25519", "ecdsa-256", "rsa-2048"}
	keyIDs := make(map[string]int64)

	for _, algo := range algos {
		kp, err := domain.GetKey(domain.KeyType(algo))
		if err != nil {
			t.Fatalf("failed to generate key for %s: %v", algo, err)
		}
		privPem, pubPem, err := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal key for %s: %v", algo, err)
		}

		dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
			Name:          "inspect-key-" + algo,
			Algorithm:     algo,
			PrivateKeyPem: string(privPem),
			PublicKeyPem:  string(pubPem),
		})
		if err != nil {
			t.Fatalf("failed to seed key %s to DB: %v", algo, err)
		}
		keyIDs[algo] = dbKey.ID
	}

	tests := []struct {
		name    string
		cmd     InspectCmd
		wantErr bool
	}{
		{
			name: "inspect Ed25519 key without validation",
			cmd: InspectCmd{
				ID:       int(keyIDs["ed25519"]),
				Validate: false,
			},
			wantErr: false,
		},
		{
			name: "inspect ECDSA key with validation",
			cmd: InspectCmd{
				ID:       int(keyIDs["ecdsa-256"]),
				Validate: true,
			},
			wantErr: false,
		},
		{
			name: "inspect RSA key with validation",
			cmd: InspectCmd{
				ID:       int(keyIDs["rsa-2048"]),
				Validate: true,
			},
			wantErr: false,
		},
		{
			name: "non-existent key ID",
			cmd: InspectCmd{
				ID:       999999,
				Validate: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Errorf("InspectCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
