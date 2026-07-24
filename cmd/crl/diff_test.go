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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestDiffCmdStructure(t *testing.T) {
	_ = DiffCmd{}
}

func TestCompareCRLs(t *testing.T) {
	// Generate a test CA
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Generate first CRL
	now := time.Now()
	crlTemplate1 := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}

	crlDER1, err := x509.CreateRevocationList(rand.Reader, crlTemplate1, caCert, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl1, err := x509.ParseRevocationList(crlDER1)
	if err != nil {
		t.Fatal(err)
	}

	// Generate second CRL (identical)
	crlTemplate2 := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	crlDER2, err := x509.CreateRevocationList(rand.Reader, crlTemplate2, caCert, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := x509.ParseRevocationList(crlDER2)
	if err != nil {
		t.Fatal(err)
	}

	// Test identical CRLs
	diffs := compareCRLs(crl1, crl2)
	if len(diffs) != 0 {
		t.Errorf("Expected 0 diffs for identical CRLs, got %d", len(diffs))
	}

	// Generate third CRL (different number)
	crlTemplate3 := &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	crlDER3, err := x509.CreateRevocationList(rand.Reader, crlTemplate3, caCert, priv)
	if err != nil {
		t.Fatal(err)
	}
	crl3, err := x509.ParseRevocationList(crlDER3)
	if err != nil {
		t.Fatal(err)
	}

	diffs = compareCRLs(crl1, crl3)
	if len(diffs) == 0 {
		t.Error("Expected diffs for different CRL numbers, got none")
	}
}
