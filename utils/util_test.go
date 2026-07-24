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

package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// ==========================================
// IP & URL Conversion & Formatting Tests
// ==========================================

func TestToNetIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		want    net.IP
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			addr:    "192.168.1.1",
			want:    net.ParseIP("192.168.1.1"),
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			addr:    "::1",
			want:    net.ParseIP("::1"),
			wantErr: false,
		},
		{
			name:    "invalid IP string",
			addr:    "invalid-ip",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty string",
			addr:    "",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ToNetIP(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToNetIP() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("ToNetIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToNetIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		addrs []string
		want  []net.IP
	}{
		{
			name:  "mix of valid and invalid IPs",
			addrs: []string{"10.0.0.1", "bad_ip", "127.0.0.1"},
			want:  nil,
		},
		{
			name:  "empty slice",
			addrs: []string{},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ToNetIPs(tt.addrs)
			if err != nil && tt.want != nil {
				t.Error(err)
			}
			if !IpSlicesEqual(got, tt.want) {
				t.Errorf("ToNetIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       string
		want    string
		wantErr bool
	}{
		{
			name:    "valid HTTP URL",
			s:       "http://example.com/path",
			want:    "http://example.com/path",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with port",
			s:       "https://localhost:8443",
			want:    "https://localhost:8443",
			wantErr: false,
		},
		{
			name:    "invalid URL format",
			s:       "http://192.168.0.%31/",
			wantErr: true,
		},
		{
			name:    "missing scheme",
			s:       "example.com/path",
			wantErr: true,
		},
		{
			name:    "missing host",
			s:       "https:///only-path",
			wantErr: true,
		},
		{
			name:    "userinfo not allowed",
			s:       "https://user:pass@example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ToURL(tt.s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got.String() != tt.want {
				t.Errorf("ToURL() = %v, want %v", got.String(), tt.want)
			}
		})
	}
}

func TestToURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		urls []string
		want []*url.URL
	}{
		{
			name: "mix of valid and invalid URLs",
			urls: []string{"https://example.com", "http://192.168.0.%31/", "http://localhost"},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ToURLs(tt.urls)
			if err != nil && tt.want != nil {
				t.Error(err)
			}
			if !UriSlicesEqual(got, tt.want) {
				t.Errorf("ToURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatIPsAndURIs(t *testing.T) {
	t.Parallel()

	t.Run("FormatIPs", func(t *testing.T) {
		t.Parallel()
		ips := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
		want := "192.168.1.1, 10.0.0.1"
		if got := FormatIPs(ips); got != want {
			t.Errorf("FormatIPs() = %v, want %v", got, want)
		}
	})

	t.Run("FormatURIs", func(t *testing.T) {
		t.Parallel()
		u1, _ := url.Parse("https://a.com")
		u2, _ := url.Parse("https://b.com")
		uris := []*url.URL{u1, u2}
		want := "https://a.com, https://b.com"
		if got := FormatURIs(uris); got != want {
			t.Errorf("FormatURIs() = %v, want %v", got, want)
		}
	})
}

// ==========================================
// String Manipulation & Parsing Tests
// ==========================================

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "standard CSV",
			in:   "apple, banana, cherry",
			want: []string{"apple", "banana", "cherry"},
		},
		{
			name: "spaces and empty items",
			in:   "  one , , two , three  ",
			want: []string{"one", "two", "three"},
		},
		{
			name: "empty or whitespace input",
			in:   "   ",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SplitCSV(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitCSV() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToSnakeCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		str  string
		want string
	}{
		{
			name: "spaces and uppercase",
			str:  "My Test Common Name",
			want: "my_test_common_name",
		},
		{
			name: "hyphens and consecutive special chars",
			str:  "hello---world__test  name",
			want: "hello_world_test_name",
		},
		{
			name: "leading and trailing whitespace",
			str:  "  spaced out  ",
			want: "spaced_out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ToSnakeCase(tt.str)
			if got != tt.want {
				t.Errorf("ToSnakeCase() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		fallback string
		want     string
	}{
		{
			name:     "path traversal attempt",
			input:    "../../etc/passwd",
			fallback: "fallback.txt",
			want:     "etcpasswd",
		},
		{
			name:     "illegal characters",
			input:    "my<file>*name?.cert",
			fallback: "fallback.txt",
			want:     "myfilename.cert",
		},
		{
			name:     "empty result falls back",
			input:    "../..",
			fallback: "default.txt",
			want:     "default.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizeFilename(tt.input, tt.fallback)
			if got != tt.want {
				t.Errorf("SanitizeFilename() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTTLToHours(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ttlStr  string
		want    int
		wantErr bool
	}{
		{name: "hours", ttlStr: "1000h", want: 1000, wantErr: false},
		{name: "days", ttlStr: "30d", want: 720, wantErr: false},
		{name: "years", ttlStr: "1y", want: 8760, wantErr: false},
		{name: "invalid unit", ttlStr: "10m", want: 0, wantErr: true},
		{name: "invalid format", ttlStr: "abc", want: 0, wantErr: true},
		{name: "zero duration", ttlStr: "0h", want: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTTLToHours(tt.ttlStr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTTLToHours() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseTTLToHours() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==========================================
// X.509 Mappings & Key Usages Tests
// ==========================================

func TestKeyUsagesAndMarshal(t *testing.T) {
	t.Parallel()

	t.Run("ParseKeyUsages", func(t *testing.T) {
		t.Parallel()
		input := []string{"digital-signature", "cert-sign", "invalid-usage"}
		want := []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign}
		got := ParseKeyUsages(input)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParseKeyUsages() = %v, want %v", got, want)
		}
	})

	t.Run("MarshalKeyUsage", func(t *testing.T) {
		t.Parallel()
		usage := x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
		got := MarshalKeyUsage(usage)
		if len(got) != 2 {
			t.Fatalf("MarshalKeyUsage() length = %d, want 2", len(got))
		}
	})
}

func TestExtKeyUsagesAndMarshal(t *testing.T) {
	t.Parallel()

	t.Run("ParseExtKeyUsages", func(t *testing.T) {
		t.Parallel()
		input := []string{"server-auth", "client-auth"}
		want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		got := ParseExtKeyUsages(input)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParseExtKeyUsages() = %v, want %v", got, want)
		}
	})

	t.Run("MarshalExtKeyUsages", func(t *testing.T) {
		t.Parallel()
		extUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning}
		want := []string{"server-auth", "code-signing"}
		got := MarshalExtKeyUsages(extUsages)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("MarshalExtKeyUsages() = %v, want %v", got, want)
		}
	})
}

func TestRevocationReasonParsingAndMarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reason  string
		code    int
		wantErr bool
	}{
		{name: "key compromise", reason: "key-compromise", code: 1, wantErr: false},
		{name: "ca compromise", reason: "ca-compromise", code: 2, wantErr: false},
		{name: "invalid reason", reason: "unknown-reason", code: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotCode, err := ParseRevocationReason(tt.reason)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRevocationReason() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if gotCode != tt.code {
					t.Errorf("ParseRevocationReason() = %d, want %d", gotCode, tt.code)
				}

				gotReason, err := MarshalRevocationReason(tt.code)
				if err != nil {
					t.Fatalf("MarshalRevocationReason() unexpected error: %v", err)
				}
				if gotReason != tt.reason {
					t.Errorf("MarshalRevocationReason() = %s, want %s", gotReason, tt.reason)
				}
			}
		})
	}
}

func TestGetSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyType string
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{name: "RSA 2048", keyType: "rsa-2048", want: x509.SHA256WithRSA, wantErr: false},
		{name: "ECDSA 256", keyType: "ecdsa-256", want: x509.ECDSAWithSHA256, wantErr: false},
		{name: "Ed25519", keyType: "ed25519", want: x509.PureEd25519, wantErr: false},
		{name: "invalid key type", keyType: "invalid-type", want: x509.UnknownSignatureAlgorithm, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := GetSignatureAlgorithm(tt.keyType)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetSignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ==========================================
// Crypto Helpers & Key Inspection Tests
// ==========================================

func TestGetKeyDetails(t *testing.T) {
	t.Parallel()

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name         string
		key          any
		wantAlgoType string
		wantSizeInfo string
	}{
		{name: "RSA Private", key: rsaPriv, wantAlgoType: "RSA Private Key", wantSizeInfo: "2048-bit"},
		{name: "ECDSA Private", key: ecdsaPriv, wantAlgoType: "ECDSA Private Key", wantSizeInfo: "Curve: P-256"},
		{name: "Ed25519 Private", key: edPriv, wantAlgoType: "Ed25519 Private Key", wantSizeInfo: "256-bit seed"},
		{name: "Unknown Type", key: "invalid", wantAlgoType: "Unknown (string)", wantSizeInfo: "N/A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			algo, size := GetKeyDetails(tt.key)
			if algo != tt.wantAlgoType || size != tt.wantSizeInfo {
				t.Errorf("GetKeyDetails() = (%s, %s), want (%s, %s)", algo, size, tt.wantAlgoType, tt.wantSizeInfo)
			}
		})
	}
}

func TestTruncateHexAndFormatFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("TruncateHex", func(t *testing.T) {
		t.Parallel()
		longBytes := bytes.Repeat([]byte{0xAA}, 20) // 40 hex chars
		got := TruncateHex(longBytes)
		if len(got) != 32 {
			t.Errorf("TruncateHex() length = %d, want 32", len(got))
		}

		if TruncateHex(nil) != "empty" {
			t.Errorf("TruncateHex(nil) failed")
		}
	})

	t.Run("FormatFingerprint", func(t *testing.T) {
		t.Parallel()
		input := []byte{0x01, 0xAB, 0xFF}
		want := "01:AB:FF"
		if got := FormatFingerprint(input); got != want {
			t.Errorf("FormatFingerprint() = %s, want %s", got, want)
		}
	})
}

func TestGetSerialNumber(t *testing.T) {
	t.Parallel()

	sNum, err := GetSerialNumber()
	if err != nil {
		t.Fatalf("GetSerialNumber() error = %v", err)
	}
	if sNum == nil || sNum.Cmp(big.NewInt(0)) <= 0 {
		t.Errorf("GetSerialNumber() returned invalid serial: %v", sNum)
	}
}

// ==========================================
// Encoding, PEM & File System Tests
// ==========================================

func TestEncodeAndDecodePem(t *testing.T) {
	t.Parallel()

	rawBytes := []byte("test-data-payload")
	blockType := "TEST BLOCK"

	pemBytes, err := EncodeToPem(rawBytes, blockType)
	if err != nil {
		t.Fatalf("EncodeToPem() error = %v", err)
	}

	decodedBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		t.Fatalf("DecodeToPem() error = %v", err)
	}

	if !bytes.Equal(decodedBytes, rawBytes) {
		t.Errorf("DecodeToPem() = %s, want %s", string(decodedBytes), string(rawBytes))
	}
}

func TestResolveDestinationPathAndReadFile(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "sample.txt")
	testContent := []byte("hello world")
	if err := os.WriteFile(testFile, testContent, 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	t.Run("ReadFile", func(t *testing.T) {
		got, err := ReadFile(testFile)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if !bytes.Equal(got, testContent) {
			t.Errorf("ReadFile() = %s, want %s", got, testContent)
		}
	})

	t.Run("ResolveDestinationPath directory", func(t *testing.T) {
		resolved, err := ResolveDestinationPath(tmpDir, "default_cert", ".crt")
		if err != nil {
			t.Fatalf("ResolveDestinationPath() error = %v", err)
		}
		expected := filepath.Join(tmpDir, "default_cert.crt")
		if resolved != expected {
			t.Errorf("ResolveDestinationPath() = %s, want %s", resolved, expected)
		}
	})
}

func TestIsSelfSigned(t *testing.T) {
	t.Parallel()

	certSelf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Root CA"},
		Issuer:  pkix.Name{CommonName: "Root CA"},
	}

	certOther := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Leaf Certificate"},
		Issuer:  pkix.Name{CommonName: "Intermediate CA"},
	}

	if !IsSelfSigned(certSelf) {
		t.Errorf("IsSelfSigned(certSelf) = false, want true")
	}

	if IsSelfSigned(certOther) {
		t.Errorf("IsSelfSigned(certOther) = true, want false")
	}
}

// ==========================================
// X.509, CSR, CRL & Key Pair Integration Tests
// ==========================================

func TestParseCSR(t *testing.T) {
	t.Parallel()

	// Generate a valid CSR
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr.example.com"},
	}
	derCSR, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	pemCSR, _ := EncodeToPem(derCSR, "CERTIFICATE REQUEST")

	t.Run("valid CSR", func(t *testing.T) {
		t.Parallel()
		csr, err := ParseCSR(string(pemCSR))
		if err != nil {
			t.Fatalf("ParseCSR() unexpected error: %v", err)
		}
		if csr.Subject.CommonName != "csr.example.com" {
			t.Errorf("ParseCSR() CommonName = %s, want csr.example.com", csr.Subject.CommonName)
		}
	})

	t.Run("invalid CSR string", func(t *testing.T) {
		t.Parallel()
		_, err := ParseCSR("invalid-pem-data")
		if err == nil {
			t.Error("ParseCSR() expected error for invalid PEM, got nil")
		}
	})
}

func TestParseCertificateAndMarshal(t *testing.T) {
	t.Parallel()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "cert.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(derBytes)

	pemBytes, err := MarshalCertificate(cert)
	if err != nil {
		t.Fatalf("MarshalCertificate() error = %v", err)
	}

	parsedCert, err := ParseCertificate(pemBytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if parsedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("ParseCertificate() CN = %s, want %s", parsedCert.Subject.CommonName, cert.Subject.CommonName)
	}
}
