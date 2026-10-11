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

package gen

import (
	"testing"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestCACmd_Run(t *testing.T) {
	// Seed key pair for signing Root CA
	kp, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := crypto.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "gen-ca-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tests := []struct {
		name    string
		cmd     CACmd
		wantErr bool
	}{
		{
			name: "generate valid Root CA certificate",
			cmd: CACmd{
				CommonName: "Gen Root CA",
				KeyID:      dbKey.ID,
				TTL:        "8760h",
				KeyUsages:  []string{"cert_sign", "crl_sign"},
			},
			wantErr: false,
		},
		{
			name: "invalid key ID returns error",
			cmd: CACmd{
				CommonName: "Gen Root CA Invalid Key",
				KeyID:      999999,
				TTL:        "8760h",
			},
			wantErr: true,
		},
		{
			name: "invalid TTL string returns error",
			cmd: CACmd{
				CommonName: "Gen Root CA Invalid TTL",
				KeyID:      dbKey.ID,
				TTL:        "invalid_ttl",
			},
			wantErr: true,
		},
		{
			name: "zero TTL returns error",
			cmd: CACmd{
				CommonName: "Gen Root CA Zero TTL",
				KeyID:      dbKey.ID,
				TTL:        "0h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CACmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
