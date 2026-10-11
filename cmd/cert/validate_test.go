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
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestValidateCmd_Run(t *testing.T) {
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "validate-cert-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	// Valid CA Certificate
	tmplValid := &x509.Certificate{
		SerialNumber:          big.NewInt(7001),
		Subject:               pkix.Name{CommonName: "Valid CA Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(240 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derValid, _ := x509.CreateCertificate(rand.Reader, tmplValid, tmplValid, kp.PublicKey, kp.PrivateKey)
	pemValid, _ := utils.EncodeToPem(derValid, "CERTIFICATE")

	dbValidCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "7001",
		CommonName:     "Valid CA Cert",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "valid-skid",
		Akid:           "valid-akid",
		Status:         "ACTIVE",
		NotBefore:      tmplValid.NotBefore,
		NotAfter:       tmplValid.NotAfter,
		CertificatePem: string(pemValid),
	})
	if err != nil {
		t.Fatalf("failed to seed valid cert: %v", err)
	}

	// Expired Certificate
	tmplExpired := &x509.Certificate{
		SerialNumber: big.NewInt(7002),
		Subject:      pkix.Name{CommonName: "Expired Cert"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	derExpired, _ := x509.CreateCertificate(rand.Reader, tmplExpired, tmplExpired, kp.PublicKey, kp.PrivateKey)
	pemExpired, _ := utils.EncodeToPem(derExpired, "CERTIFICATE")

	dbExpiredCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "7002",
		CommonName:     "Expired Cert",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "expired-skid",
		Akid:           "expired-akid",
		Status:         "EXPIRED",
		NotBefore:      tmplExpired.NotBefore,
		NotAfter:       tmplExpired.NotAfter,
		CertificatePem: string(pemExpired),
	})
	if err != nil {
		t.Fatalf("failed to seed expired cert: %v", err)
	}

	tests := []struct {
		name    string
		cmd     ValidateCmd
		wantErr bool
	}{
		{
			name: "validate active valid cert",
			cmd: ValidateCmd{
				ID: dbValidCert.ID,
			},
			wantErr: false,
		},
		{
			name: "validate expired cert returns error",
			cmd: ValidateCmd{
				ID: dbExpiredCert.ID,
			},
			wantErr: true,
		},
		{
			name: "validate non-existent cert ID",
			cmd: ValidateCmd{
				ID: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
