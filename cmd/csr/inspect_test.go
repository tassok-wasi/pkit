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

func TestInspectCmd_Run(t *testing.T) {
	kp, _ := domain.GetKey(domain.ED25519)
	privKeyPem, pubKeyPem, err := utils.MarshalKeys(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Error(err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "inspect.example.com" + t.Name(),
		Algorithm:     string(domain.ED25519),
		PrivateKeyPem: string(privKeyPem),
		PublicKeyPem:  string(pubKeyPem),
	})
	if err != nil {
		t.Error(err)
	}

	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "inspect.example.com"},
		DNSNames: []string{"inspect.example.com", "alt.example.com"},
	}
	derCSR, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, kp.PrivateKey)
	pemCSR, _ := utils.EncodeToPem(derCSR, "CERTIFICATE REQUEST")

	dbCSR, err := testQuerier.CreateCSR(testCtx, base.CreateCSRParams{
		CommonName: "inspect.example.com",
		KeyID:      dbKey.ID,
		CsrPem:     string(pemCSR),
		Status:     "PENDING",
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}

	tests := []struct {
		name    string
		cmd     InspectCmd
		wantErr bool
	}{
		{
			name:    "inspect existing CSR",
			cmd:     InspectCmd{ID: dbCSR.ID},
			wantErr: false,
		},
		{
			name:    "non-existent CSR returns error",
			cmd:     InspectCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("InspectCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
