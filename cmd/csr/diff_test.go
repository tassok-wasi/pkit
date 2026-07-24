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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCompareCSRs(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template1 := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.com",
			Country:    []string{"US"},
		},
		DNSNames: []string{"example.com"},
	}
	csr1Bytes, err := x509.CreateCertificateRequest(rand.Reader, template1, key)
	if err != nil {
		t.Fatalf("failed to create CSR 1: %v", err)
	}
	csr1, err := x509.ParseCertificateRequest(csr1Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR 1: %v", err)
	}

	template2 := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.org",
			Country:    []string{"CA"},
		},
		DNSNames: []string{"example.org"},
	}
	csr2Bytes, err := x509.CreateCertificateRequest(rand.Reader, template2, key)
	if err != nil {
		t.Fatalf("failed to create CSR 2: %v", err)
	}
	csr2, err := x509.ParseCertificateRequest(csr2Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR 2: %v", err)
	}

	tests := []struct {
		name        string
		csr1        *x509.CertificateRequest
		csr2        *x509.CertificateRequest
		expectDiffs bool
	}{
		{
			name:        "identical CSRs",
			csr1:        csr1,
			csr2:        csr1,
			expectDiffs: false,
		},
		{
			name:        "different CSRs",
			csr1:        csr1,
			csr2:        csr2,
			expectDiffs: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diffs := compareCSRs(tt.csr1, tt.csr2)
			if (len(diffs) > 0) != tt.expectDiffs {
				t.Errorf("compareCSRs() diff count = %d, expectDiffs = %v", len(diffs), tt.expectDiffs)
			}
		})
	}
}

func TestDiffCmd(t *testing.T) {
	t.Parallel()

	cmd := DiffCmd{ID1: 1, ID2: 2}
	if cmd.ID1 != 1 {
		t.Errorf("Expected ID1 to be 1, got %d", cmd.ID1)
	}
}
