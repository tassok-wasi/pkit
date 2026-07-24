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

package cert

import (
	"database/sql"
	"testing"
	"time"

	"pkit/db/base"
)

func TestListCmd_Run(t *testing.T) {
	// Seed dummy key and certs for testing list and filters
	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "list-test-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: "dummy_priv",
		PublicKeyPem:  "dummy_pub",
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	certsToSeed := []struct {
		serial    string
		cn        string
		cType     string
		status    string
		isRevoked int
	}{
		{serial: "3001", cn: "List Root CA", cType: "CA", status: "ACTIVE", isRevoked: 0},
		{serial: "3002", cn: "List Leaf Active", cType: "LEAF", status: "ACTIVE", isRevoked: 0},
		{serial: "3003", cn: "List Leaf Revoked", cType: "LEAF", status: "REVOKED", isRevoked: 1},
	}

	for _, c := range certsToSeed {
		_, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
			SerialNumber: c.serial,
			CommonName:   c.cn,
			Type:         c.cType,
			KeyID:        dbKey.ID,
			Skid:         "skid-" + c.serial,
			Akid:         "akid-" + c.serial,
			Status:       c.status,
			IsRevoked: sql.NullInt64{Int64: int64(c.isRevoked), Valid: func() bool {
				if c.isRevoked == 1 {
					return true
				}
				return false
			}()},
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(24 * time.Hour),
			CertificatePem: "dummy_pem",
		})
		if err != nil {
			t.Fatalf("failed to seed cert %s: %v", c.serial, err)
		}
	}

	tests := []struct {
		name    string
		cmd     ListCmd
		wantErr bool
	}{
		{
			name: "list all certificates",
			cmd: ListCmd{
				Limit:  0,
				Offset: 0,
			},
			wantErr: false,
		},
		{
			name: "filter by status ACTIVE",
			cmd: ListCmd{
				Status: "ACTIVE",
			},
			wantErr: false,
		},
		{
			name: "filter by type CA",
			cmd: ListCmd{
				Type: "CA",
			},
			wantErr: false,
		},
		{
			name: "paginated listing with limit and offset",
			cmd: ListCmd{
				Limit:  2,
				Offset: 1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testDB, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
