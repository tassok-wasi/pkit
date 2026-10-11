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

package gen

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

func TestIntermediateCmd_Run(t *testing.T) {
	// Seed Parent Root Key & Cert
	rootKp, _ := domain.GetKey(domain.ED25519)
	rootPrivPem, rootPubPem, _ := utils.ReturnPrivPubPem(rootKp.PrivateKey, rootKp.PublicKey)
	dbRootKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "inter-root-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(rootPrivPem),
		PublicKeyPem:  string(rootPubPem),
	})

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: "Parent Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derRoot, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKp.PublicKey, rootKp.PrivateKey)
	pemRoot, _ := utils.EncodeToPem(derRoot, "CERTIFICATE")

	dbRootCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "9001",
		CommonName:     "Parent Root CA",
		Type:           "CA",
		KeyID:          dbRootKey.ID,
		Skid:           "parent-skid",
		Akid:           "parent-akid",
		Status:         "ACTIVE",
		NotBefore:      rootTmpl.NotBefore,
		NotAfter:       rootTmpl.NotAfter,
		CertificatePem: string(pemRoot),
	})
	if err != nil {
		t.Fatalf("failed to seed parent root cert: %v", err)
	}

	// 2. Seed Intermediate Key
	interKp, _ := domain.GetKey(domain.ED25519)
	interPrivPem, interPubPem, _ := utils.ReturnPrivPubPem(interKp.PrivateKey, interKp.PublicKey)
	dbInterKey, _ := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "inter-target-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(interPrivPem),
		PublicKeyPem:  string(interPubPem),
	})

	tests := []struct {
		name    string
		cmd     ICACmd
		wantErr bool
	}{
		{
			name: "generate valid Intermediate CA certificate",
			cmd: ICACmd{
				CommonName: "Gen Intermediate CA",
				KeyID:      dbInterKey.ID,
				IssuerID:   dbRootCert.ID,
				TTL:        "4380h",
				KeyUsages:  []string{"cert_sign", "crl_sign"},
				PathLen:    1,
			},
			wantErr: false,
		},
		{
			name: "non-existent issuer cert ID returns error",
			cmd: ICACmd{
				CommonName: "Gen Intermediate CA Bad Issuer",
				KeyID:      dbInterKey.ID,
				IssuerID:   999999,
				TTL:        "4380h",
			},
			wantErr: true,
		},
		{
			name: "non-existent key ID returns error",
			cmd: ICACmd{
				CommonName: "Gen Intermediate CA Bad Key",
				KeyID:      999999,
				IssuerID:   dbRootCert.ID,
				TTL:        "4380h",
			},
			wantErr: true,
		},
		{
			name: "zero TTL returns error",
			cmd: ICACmd{
				CommonName: "Gen Intermediate CA Zero TTL",
				KeyID:      dbInterKey.ID,
				IssuerID:   dbRootCert.ID,
				TTL:        "0h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testDB, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IntermediateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
