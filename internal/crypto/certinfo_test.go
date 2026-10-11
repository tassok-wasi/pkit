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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestGetSerialNumber(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	for i := 0; i < 20; i++ {
		sn, err := GetSerialNumber()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sn == nil {
			t.Fatal("expected non-nil serial number")
		}
		if sn.Sign() <= 0 {
			t.Fatalf("expected positive serial number, got %s", sn)
		}
		if sn.Cmp(limit) >= 0 {
			t.Fatalf("serial number %s exceeds 128 bits", sn)
		}
	}
}

func TestGetKeyDetails(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	tests := []struct {
		name         string
		key          any
		wantAlgo     string
		wantSizeInfo string
	}{
		{"rsa private", rsaKey, "RSA Private Key", "2048-bit"},
		{"rsa public", &rsaKey.PublicKey, "RSA Public Key", "2048-bit"},
		{"ecdsa private", ecdsaKey, "ECDSA Private Key", "Curve: P-256"},
		{"ecdsa public", &ecdsaKey.PublicKey, "ECDSA Public Key", "Curve: P-256"},
		{"ed25519 private", edPriv, "Ed25519 Private Key", "256-bit seed"},
		{"ed25519 public", edPub, "Ed25519 Public Key", "256-bit"},
		{"unknown", "not-a-key", "Unknown (string)", "N/A"},
		{"nil", nil, "Unknown (<nil>)", "N/A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, size := GetKeyDetails(tt.key)
			if algo != tt.wantAlgo {
				t.Fatalf("algo = %q, want %q", algo, tt.wantAlgo)
			}
			if size != tt.wantSizeInfo {
				t.Fatalf("size = %q, want %q", size, tt.wantSizeInfo)
			}
		})
	}
}

func TestTruncateHex(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, "empty"},
		{"empty non-nil", []byte{}, "empty"},
		{"short", []byte{0x01, 0x02, 0x03}, "010203"},
		{"exactly 16 bytes", bytes.Repeat([]byte{0xAB}, 16), "abababababababababababababababab"},
		{"longer than 16 bytes", bytes.Repeat([]byte{0xAB}, 20), "abababababababababababababababab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateHex(tt.in)
			if got != tt.want {
				t.Fatalf("TruncateHex(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"single", []byte{0x01}, "01"},
		{"multiple", []byte{0xAA, 0xBB, 0xCC}, "AA:BB:CC"},
		{"pads single digit", []byte{0x0F, 0x00}, "0F:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatFingerprint(tt.in)
			if got != tt.want {
				t.Fatalf("FormatFingerprint(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractAuthorityKeyID(t *testing.T) {
	t.Run("extracts key identifier", func(t *testing.T) {
		keyID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		val, err := asn1.Marshal(authKeyIdentifier{KeyIdentifier: keyID})
		if err != nil {
			t.Fatalf("failed to marshal akid: %v", err)
		}
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: val},
			},
		}

		got, err := ExtractAuthorityKeyID(cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, keyID) {
			t.Fatalf("got %x, want %x", got, keyID)
		}
	})

	t.Run("returns error when extension missing", func(t *testing.T) {
		cert := &x509.Certificate{}
		if _, err := ExtractAuthorityKeyID(cert); err == nil {
			t.Fatal("expected error when AKID extension is absent")
		}
	})

	t.Run("returns error on malformed extension", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: []byte{0xFF, 0xFF}},
			},
		}
		if _, err := ExtractAuthorityKeyID(cert); err == nil {
			t.Fatal("expected error on malformed AKID extension")
		}
	})
}

func TestIsSelfSigned(t *testing.T) {
	t.Run("self signed", func(t *testing.T) {
		name := pkix.Name{CommonName: "root", Organization: []string{"Acme"}}
		cert := &x509.Certificate{Subject: name, Issuer: name}
		if !IsSelfSigned(cert) {
			t.Fatal("expected certificate to be self-signed")
		}
	})

	t.Run("not self signed", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "leaf"},
			Issuer:  pkix.Name{CommonName: "root"},
		}
		if IsSelfSigned(cert) {
			t.Fatal("expected certificate not to be self-signed")
		}
	})
}
