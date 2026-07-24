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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"pkit/db/base"
	"pkit/domain"
	"pkit/utils"
)

func TestVerifyCmd_Run(t *testing.T) {
	kp, _ := domain.GetKey(domain.ED25519)
	privPem, pubPem, err := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "csr-verify-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Error(err)
	}

	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "verify.example.com"},
	}
	derCSR, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, kp.PrivateKey)
	pemCSR, _ := utils.EncodeToPem(derCSR, "CERTIFICATE REQUEST")

	dbCSR, err := testQuerier.CreateCSR(testCtx, base.CreateCSRParams{
		CommonName: "verify.example.com",
		CsrPem:     string(pemCSR),
		Status:     "PENDING",
		KeyID:      dbKey.ID,
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tests := []struct {
		name    string
		cmd     VerifyCmd
		wantErr bool
	}{
		{
			name:    "verify valid CSR self-signature without key check",
			cmd:     VerifyCmd{ID: dbCSR.ID},
			wantErr: false,
		},
		{
			name:    "verify valid CSR with matching KeyID check",
			cmd:     VerifyCmd{ID: dbCSR.ID},
			wantErr: false,
		},
		{
			name:    "non-existent CSR ID returns error",
			cmd:     VerifyCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
