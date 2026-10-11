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

	"github.com/tassok-wasi/pkit/db/base"
)

func TestListCmd_Run(t *testing.T) {
	// Seed multiple keys to test pagination
	for i := 1; i <= 3; i++ {
		_, _ = testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
			Name:          "list-key-" + string(rune('0'+i)),
			Algorithm:     "ed25519",
			PrivateKeyPem: "dummy_priv",
			PublicKeyPem:  "dummy_pub",
		})
	}

	tests := []struct {
		name    string
		cmd     ListCmd
		wantErr bool
	}{
		{
			name: "list all keys (no limit/offset)",
			cmd: ListCmd{
				Limit:  0,
				Offset: 0,
			},
			wantErr: false,
		},
		{
			name: "list paginated keys with limit and offset",
			cmd: ListCmd{
				Limit:  2,
				Offset: 1,
			},
			wantErr: false,
		},
		{
			name: "list offset beyond available rows",
			cmd: ListCmd{
				Limit:  10,
				Offset: 100,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testDB, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
