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
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestValidateCmd_Run(t *testing.T) {
	ctx := context.Background()

	kp, _ := pki.GetKey(pki.ED25519)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7301),
		Subject:               pkix.Name{CommonName: "CRL Validate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(87600 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derIssuer, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	parsedIssuer, _ := x509.ParseCertificate(derIssuer)

	now := time.Now()

	// 1. Valid CRL
	validTmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-1 * time.Hour),
		NextUpdate: now.Add(168 * time.Hour),
	}
	validDER, _ := x509.CreateRevocationList(rand.Reader, validTmpl, parsedIssuer, kp.PrivateKey.(stdcrypto.Signer))
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: validDER})

	dbValidCRL, _ := testQuerier.CreateCRL(ctx, sqlc.CreateCRLParams{
		Name:       "Valid_CRL",
		CrlNumber:  1,
		IssuerID:   1,
		ThisUpdate: validTmpl.ThisUpdate,
		NextUpdate: validTmpl.NextUpdate,
		CrlPem:     string(validPEM),
	})

	// 2. Expired CRL
	expiredTmpl := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-48 * time.Hour),
		NextUpdate: now.Add(-24 * time.Hour),
	}
	expiredDER, _ := x509.CreateRevocationList(rand.Reader, expiredTmpl, parsedIssuer, kp.PrivateKey.(stdcrypto.Signer))
	expiredPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: expiredDER})

	dbExpiredCRL, _ := testQuerier.CreateCRL(ctx, sqlc.CreateCRLParams{
		Name:       "Expired_CRL",
		CrlNumber:  2,
		IssuerID:   1,
		ThisUpdate: expiredTmpl.ThisUpdate,
		NextUpdate: expiredTmpl.NextUpdate,
		CrlPem:     string(expiredPEM),
	})

	tests := []struct {
		name    string
		cmd     ValidateCmd
		wantErr bool
	}{
		{
			name:    "valid CRL passes validation",
			cmd:     ValidateCmd{ID: dbValidCRL.ID},
			wantErr: true,
		},
		{
			name:    "expired CRL fails validation",
			cmd:     ValidateCmd{ID: dbExpiredCRL.ID},
			wantErr: true,
		},
		{
			name:    "non-existent CRL returns error",
			cmd:     ValidateCmd{ID: 999999},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(ctx, testSvc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
