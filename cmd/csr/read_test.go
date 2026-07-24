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

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestReadCmd_Run(t *testing.T) {
	kp, _ := domain.GetKey(domain.ED25519)
	privKeyPem, pubKeyPem, err := utils.MarshalKeys(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "read.example.com" + t.Name(),
		Algorithm:     string(domain.ED25519),
		PrivateKeyPem: string(privKeyPem),
		PublicKeyPem:  string(pubKeyPem),
	})
	if err != nil {
		t.Error(err)
	}

	dbCSR, err := testQuerier.CreateCSR(testCtx, base.CreateCSRParams{
		CommonName: "read.example.com",
		CsrPem:     "-----BEGIN CERTIFICATE REQUEST-----\nTEST_PEM_DATA\n-----END CERTIFICATE REQUEST-----",
		Status:     "PENDING",
		KeyID:      dbKey.ID,
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ReadCmd
		wantErr bool
	}{
		{
			name:    "read existing CSR raw PEM",
			cmd:     ReadCmd{ID: dbCSR.ID},
			wantErr: false,
		},
		{
			name:    "read non-existent CSR returns error",
			cmd:     ReadCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
