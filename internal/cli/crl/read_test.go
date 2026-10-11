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

package crl

import (
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestReadCmd_Run(t *testing.T) {
	now := time.Now()
	dbCRL, err := testQuerier.CreateCRL(testCtx, sqlc.CreateCRLParams{
		Name:       "Read_CRL_Test",
		CrlNumber:  5,
		IssuerID:   1,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		CrlPem:     "-----BEGIN X509 CRL-----\nTEST_PEM_DATA\n-----END X509 CRL-----",
	})
	if err != nil {
		t.Fatalf("failed to seed CRL: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ReadCmd
		wantErr bool
	}{
		{
			name:    "read existing CRL details",
			cmd:     ReadCmd{ID: dbCRL.ID},
			wantErr: false,
		},
		{
			name:    "read non-existent CRL returns error",
			cmd:     ReadCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
