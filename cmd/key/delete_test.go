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
	"time"

	"pkit/db/base"
)

func TestDeleteCmd_Run(t *testing.T) {
	deletableKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "delete-free-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: "priv-free",
		PublicKeyPem:  "pub-free",
	})
	if err != nil {
		t.Fatalf("failed to seed deletable key: %v", err)
	}

	inUseKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "delete-in-use-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: "priv-used",
		PublicKeyPem:  "pub-used",
	})
	if err != nil {
		t.Fatalf("failed to seed in-use key: %v", err)
	}

	_, err = testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:       "delete-key-cert-1",
		CommonName:         "Delete Key Cert",
		Type:               "LEAF",
		KeyID:              inUseKey.ID,
		IssuerSerialNumber: base.CreateCertificateParams{}.IssuerSerialNumber,
		Skid:               "delete-key-cert-skid",
		Akid:               "delete-key-cert-akid",
		Status:             "ACTIVE",
		IsRevoked:          base.CreateCertificateParams{}.IsRevoked,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(24 * time.Hour),
		CertificatePem:     "dummy-cert-pem",
	})
	if err != nil {
		t.Fatalf("failed to seed certificate using key: %v", err)
	}

	tests := []struct {
		name       string
		cmd        DeleteCmd
		wantErr    bool
		verifyGone bool
	}{
		{
			name: "delete unused key successfully",
			cmd: DeleteCmd{
				ID: deletableKey.ID,
			},
			wantErr:    false,
			verifyGone: true,
		},
		{
			name: "delete key that is still referenced returns error",
			cmd: DeleteCmd{
				ID: inUseKey.ID,
			},
			wantErr: true,
		},
		{
			name: "delete non-existent key returns error",
			cmd: DeleteCmd{
				ID: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeleteCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.verifyGone {
				_, err := testQuerier.GetKeyByID(testCtx, tt.cmd.ID)
				if err == nil {
					t.Fatalf("expected key %d to be deleted, but it still exists", tt.cmd.ID)
				}
			}
		})
	}
}
