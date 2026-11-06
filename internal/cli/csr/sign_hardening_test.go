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
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func seedSigningIssuer(t *testing.T) (sqlc.Key, sqlc.Certificate) {
	t.Helper()

	kp, err := pki.GetKey(pki.ED25519)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}
	privPem, pubPem, err := crypto.ReturnPrivPubPem(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal issuer key: %v", err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          "hardening-issuer-key-" + t.Name(),
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer key: %v", err)
	}

	serial := time.Now().UnixNano()
	serialString := strconv.FormatInt(serial, 10)
	skid := []byte("hardening-issuer-skid")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Hardening Issuer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(8760 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.PublicKey, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create issuer cert: %v", err)
	}
	pemBytes, err := crypto.EncodeToPem(der, "CERTIFICATE")
	if err != nil {
		t.Fatalf("failed to encode issuer cert: %v", err)
	}

	dbCert, err := testQuerier.CreateCertificate(testCtx, sqlc.CreateCertificateParams{
		SerialNumber:   serialString,
		CommonName:     "Hardening Issuer CA",
		Type:           "CA",
		KeyID:          dbKey.ID,
		Skid:           "hardening-issuer-skid",
		Akid:           "hardening-issuer-skid",
		Status:         "ACTIVE",
		NotBefore:      tmpl.NotBefore,
		NotAfter:       tmpl.NotAfter,
		CertificatePem: string(pemBytes),
	})
	if err != nil {
		t.Fatalf("failed to seed issuer cert: %v", err)
	}
	return dbKey, dbCert
}

func seedPendingCSR(t *testing.T, name, commonName string, kp *pki.KeyPair) sqlc.Csr {
	t.Helper()

	privPem, pubPem, err := crypto.MarshalKeys(kp.PrivateKey, kp.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal CSR key: %v", err)
	}
	dbKey, err := testQuerier.CreateKeyPair(testCtx, sqlc.CreateKeyPairParams{
		Name:          name,
		Algorithm:     "ed25519",
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
	})
	if err != nil {
		t.Fatalf("failed to seed CSR key: %v", err)
	}

	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, kp.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	pemBytes, err := crypto.EncodeToPem(der, "CERTIFICATE REQUEST")
	if err != nil {
		t.Fatalf("failed to encode CSR: %v", err)
	}

	record, err := testQuerier.CreateCSR(testCtx, sqlc.CreateCSRParams{
		CommonName: commonName,
		KeyID:      dbKey.ID,
		Status:     "PENDING",
		CsrPem:     string(pemBytes),
	})
	if err != nil {
		t.Fatalf("failed to seed CSR: %v", err)
	}
	return record
}

func TestSignCSR_StatusIsolationByName(t *testing.T) {
	_, issuer := seedSigningIssuer(t)

	kp1, _ := pki.GetKey(pki.ED25519)
	kp2, _ := pki.GetKey(pki.ED25519)
	csr1 := seedPendingCSR(t, "isolation-key-1", "same.example.com", kp1)
	csr2 := seedPendingCSR(t, "isolation-key-2", "same.example.com", kp2)

	if err := (&SignCmd{
		ID:       csr1.ID,
		IssuerID: issuer.ID,
		Type:     "LEAF",
		TTL:      "24h",
	}).Run(testCtx, testSvc); err != nil {
		t.Fatalf("failed to sign first CSR: %v", err)
	}

	got1, err := testQuerier.GetCSRByID(testCtx, csr1.ID)
	if err != nil {
		t.Fatalf("failed to read first CSR: %v", err)
	}
	got2, err := testQuerier.GetCSRByID(testCtx, csr2.ID)
	if err != nil {
		t.Fatalf("failed to read second CSR: %v", err)
	}
	if got1.Status != "SIGNED" {
		t.Fatalf("first CSR status = %s, want SIGNED", got1.Status)
	}
	if got2.Status != "PENDING" {
		t.Fatalf("second CSR status = %s, want PENDING", got2.Status)
	}
}

func TestSignCSR_RejectsAlreadySigned(t *testing.T) {
	_, issuer := seedSigningIssuer(t)
	kp, _ := pki.GetKey(pki.ED25519)
	record := seedPendingCSR(t, "double-sign-key", "double.example.com", kp)

	cmd := &SignCmd{ID: record.ID, IssuerID: issuer.ID, Type: "LEAF", TTL: "24h"}
	if err := cmd.Run(testCtx, testSvc); err != nil {
		t.Fatalf("first signing failed: %v", err)
	}
	if err := cmd.Run(testCtx, testSvc); err == nil {
		t.Fatal("expected second signing to be rejected")
	}
}

func TestSignCSR_RejectsInvalidSignatureAndType(t *testing.T) {
	_, issuer := seedSigningIssuer(t)
	kp, _ := pki.GetKey(pki.ED25519)
	record := seedPendingCSR(t, "bad-signature-key", "bad.example.com", kp)

	// Corrupt the CSR signature while keeping the PEM parseable.
	block, _ := crypto.DecodeToPem([]byte(record.CsrPem))
	block[len(block)-1] ^= 0xff
	tamperedPem, err := crypto.EncodeToPem(block, "CERTIFICATE REQUEST")
	if err != nil {
		t.Fatalf("failed to encode tampered CSR: %v", err)
	}
	if _, err := testDB.ExecContext(testCtx, "UPDATE csrs SET csr_pem = ? WHERE id = ?", string(tamperedPem), record.ID); err != nil {
		t.Fatalf("failed to tamper CSR: %v", err)
	}
	if err := (&SignCmd{ID: record.ID, IssuerID: issuer.ID, Type: "LEAF", TTL: "24h"}).Run(testCtx, testSvc); err == nil {
		t.Fatal("expected invalid CSR signature to be rejected")
	}

	valid := seedPendingCSR(t, "invalid-type-key", "type.example.com", kp)
	if err := (&SignCmd{ID: valid.ID, IssuerID: issuer.ID, Type: "CA", TTL: "24h"}).Run(testCtx, testSvc); err == nil {
		t.Fatal("expected CA CSR signing to be rejected")
	}
}
