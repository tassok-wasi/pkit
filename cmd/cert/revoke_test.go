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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"testing"
	"time"

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestRevokeCmd_Run(t *testing.T) {
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, err := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "revoke-cert-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5001),
		Subject:      pkix.Name{CommonName: "Revoke Target Cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	pem, _ := utils.EncodeToPem(der, "CERTIFICATE")

	dbCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "5001",
		CommonName:     "Revoke Target Cert",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "revoke-skid",
		Akid:           "revoke-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: false},
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pem),
	})
	if err != nil {
		t.Fatalf("failed to seed cert: %v", err)
	}

	tests := []struct {
		name    string
		cmd     RevokeCmd
		wantErr bool
	}{
		{
			name: "revoke active certificate successfully",
			cmd: RevokeCmd{
				ID:     dbCert.ID,
				Reason: "key-compromise",
			},
			wantErr: false,
		},
		{
			name: "revoke already revoked certificate",
			cmd: RevokeCmd{
				ID:     dbCert.ID,
				Reason: "unspecified",
			},
			wantErr: true,
		},
		{
			name: "revoke non-existent cert ID",
			cmd: RevokeCmd{
				ID:     999999,
				Reason: "key-compromise",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RevokeCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
