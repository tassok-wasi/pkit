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

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestListCmd_Run(t *testing.T) {
	kp, _ := domain.GetKey(domain.ED25519)
	privKeyPem, pubKeyPem, err := utils.MarshalKeys(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "list.example.com" + t.Name(),
		Algorithm:     string(domain.ED25519),
		PrivateKeyPem: string(privKeyPem),
		PublicKeyPem:  string(pubKeyPem),
	})
	if err != nil {
		t.Error(err)
	}

	_, err = testQuerier.CreateCSR(testCtx, base.CreateCSRParams{
		CommonName: "list.example.com",
		CsrPem:     "PEM_DATA",
		Status:     "PENDING",
		KeyID:      dbKey.ID,
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ListCmd
		wantErr bool
	}{
		{
			name:    "list CSRs without limit or offset",
			cmd:     ListCmd{},
			wantErr: false,
		},
		{
			name:    "list CSRs with pagination limit and offset",
			cmd:     ListCmd{Limit: 10, Offset: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
