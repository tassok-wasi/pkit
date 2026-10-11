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

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEncodeDecodeToPem(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		der := []byte{0x01, 0x02, 0x03, 0x04}
		encoded, err := EncodeToPem(der, "TEST BLOCK")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		block, _ := pem.Decode(encoded)
		if block == nil {
			t.Fatal("expected valid PEM block")
		}
		if block.Type != "TEST BLOCK" {
			t.Fatalf("block type = %q, want %q", block.Type, "TEST BLOCK")
		}

		decoded, err := DecodeToPem(encoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(decoded, der) {
			t.Fatalf("decoded = %x, want %x", decoded, der)
		}
	})

	t.Run("decode invalid input", func(t *testing.T) {
		if _, err := DecodeToPem([]byte("not a pem")); err == nil {
			t.Fatal("expected error decoding invalid PEM")
		}
	})
}

func makeSelfSignedCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func TestMarshalParseCertificate(t *testing.T) {
	cert := makeSelfSignedCert(t, 4242)

	pemBytes, err := MarshalCertificate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %v", block)
	}

	parsed, err := ParseCertificate(pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("serial mismatch: got %s, want %s", parsed.SerialNumber, cert.SerialNumber)
	}
	if parsed.Subject.CommonName != "test.example.com" {
		t.Fatalf("common name = %q, want %q", parsed.Subject.CommonName, "test.example.com")
	}
}

func TestParseCertificateInvalid(t *testing.T) {
	t.Run("invalid pem", func(t *testing.T) {
		if _, err := ParseCertificate([]byte("not a pem")); err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})

	t.Run("valid pem but invalid der", func(t *testing.T) {
		pemBytes, err := EncodeToPem([]byte{0x01, 0x02, 0x03}, "CERTIFICATE")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := ParseCertificate(pemBytes); err == nil {
			t.Fatal("expected error for invalid DER")
		}
	})
}

func TestParseCRL(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	pemBytes, err := EncodeToPem(crlDER, "X509 CRL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	crl, err := ParseCRL(pemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("CRL number = %s, want 7", crl.Number)
	}
}

func TestParseCRLInvalid(t *testing.T) {
	if _, err := ParseCRL([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParseCSR(t *testing.T) {
	t.Run("valid csr", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		csrTmpl := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "csr.example.com"},
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
		if err != nil {
			t.Fatalf("failed to create CSR: %v", err)
		}
		pemBytes, err := EncodeToPem(csrDER, "CERTIFICATE REQUEST")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		csr, err := ParseCSR(string(pemBytes))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if csr.Subject.CommonName != "csr.example.com" {
			t.Fatalf("common name = %q, want %q", csr.Subject.CommonName, "csr.example.com")
		}
	})

	t.Run("invalid pem", func(t *testing.T) {
		if _, err := ParseCSR("not a pem"); err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})

	t.Run("wrong block type", func(t *testing.T) {
		pemBytes, err := EncodeToPem([]byte{0x01, 0x02, 0x03}, "CERTIFICATE")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := ParseCSR(string(pemBytes)); err == nil {
			t.Fatal("expected error for wrong PEM block type")
		}
	})
}
