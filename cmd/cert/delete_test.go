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

	"github.com/tassok-wasi/pkit/db/base"
	"github.com/tassok-wasi/pkit/domain"
	"github.com/tassok-wasi/pkit/utils"
)

func TestDeleteCmd_Run(t *testing.T) {
	// Seed key
	kp, err := domain.GetKey(domain.ED25519)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privPem, pubPem, _ := utils.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)

	dbKey, err := testQuerier.CreateKeyPair(testCtx, base.CreateKeyPairParams{
		Name:          "cert-delete-key",
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}

	// Seed free-standing cert (no foreign-key references pointing to it)
	dbFreeCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "cert-delete-free",
		CommonName:     "Delete Free Cert",
		Type:           "LEAF",
		KeyID:          dbKey.ID,
		Skid:           "delete-free-skid",
		Akid:           "delete-free-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		CertificatePem: "dummy-pem-free",
	})
	if err != nil {
		t.Fatalf("failed to seed free cert: %v", err)
	}

	// Seed referenced cert (referenced by a CRL)
	dbRefCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "cert-delete-ref",
		CommonName:     "Delete Ref Cert",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "delete-ref-skid",
		Akid:           "delete-ref-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		CertificatePem: "dummy-pem-ref",
	})
	if err != nil {
		t.Fatalf("failed to seed ref cert: %v", err)
	}

	// Create a CRL referencing the issuer cert
	_, err = testQuerier.CreateCRL(testCtx, base.CreateCRLParams{
		Name:       "blocking-crl",
		CrlNumber:  1,
		IssuerID:   dbRefCert.ID,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(168 * time.Hour),
		CrlPem:     "dummy-crl-pem",
	})
	if err != nil {
		t.Fatalf("failed to seed blocking CRL: %v", err)
	}

	// Seed a cert referenced by another cert's issuer_serial_number
	dbIssuerCert, err := testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:   "cert-issuer-ref-sn",
		CommonName:     "Issuer Ref Cert",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "issuer-ref-skid",
		Akid:           "issuer-ref-akid",
		Status:         "ACTIVE",
		IsRevoked:      sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		CertificatePem: "dummy-pem-issuer",
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}

	_, err = testQuerier.CreateCertificate(testCtx, base.CreateCertificateParams{
		SerialNumber:       "cert-child-ref-sn",
		CommonName:         "Child Cert",
		Type:               "LEAF",
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: "cert-issuer-ref-sn", Valid: true},
		Skid:               "child-skid",
		Akid:               "child-akid",
		Status:             "ACTIVE",
		IsRevoked:          sql.NullInt64{Int64: 0, Valid: true},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(24 * time.Hour),
		CertificatePem:     "dummy-pem-child",
	})
	if err != nil {
		t.Fatalf("failed to seed child cert: %v", err)
	}

	tests := []struct {
		name       string
		cmd        DeleteCmd
		wantErr    bool
		verifyGone bool
	}{
		{
			name: "delete unreferenced certificate successfully",
			cmd: DeleteCmd{
				ID: dbFreeCert.ID,
			},
			wantErr:    false,
			verifyGone: true,
		},
		{
			name: "delete certificate used as CRL issuer returns error",
			cmd: DeleteCmd{
				ID: dbRefCert.ID,
			},
			wantErr: true,
		},
		{
			name: "delete certificate referenced as issuer by another cert still works",
			cmd: DeleteCmd{
				ID: dbIssuerCert.ID,
			},
			wantErr:    false,
			verifyGone: true,
		},
		{
			name: "delete non-existent certificate returns error",
			cmd: DeleteCmd{
				ID: 999999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Run(testCtx, testQuerier)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeleteCmd.Run() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.verifyGone {
				_, err := testQuerier.GetCertificateByID(testCtx, tt.cmd.ID)
				if err == nil {
					t.Fatalf("expected certificate %d to be deleted, but it still exists", tt.cmd.ID)
				}
			}
		})
	}
}
