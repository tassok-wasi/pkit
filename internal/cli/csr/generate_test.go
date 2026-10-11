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
	"testing"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestGenerateCmd_Run(t *testing.T) {
	// Seed Key Pair
	kp, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := crypto.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "csr-gen-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tests := []struct {
		name    string
		cmd     GenerateCmd
		wantErr bool
	}{
		{
			name: "generate valid CSR with SANs",
			cmd: GenerateCmd{
				CommonName:  "app.example.com",
				KeyID:       dbKey.ID,
				DNSNames:    []string{"app.example.com", "api.example.com"},
				IPAddresses: []string{"192.168.1.100"},
			},
			wantErr: false,
		},
		{
			name: "invalid IP address format returns error",
			cmd: GenerateCmd{
				CommonName:  "badip.example.com",
				KeyID:       dbKey.ID,
				IPAddresses: []string{"invalid_ip_addr"},
			},
			wantErr: true,
		},
		{
			name: "non-existent key ID returns error",
			cmd: GenerateCmd{
				CommonName: "nokey.example.com",
				KeyID:      999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
