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
	"crypto/x509"
	"reflect"
	"sort"
	"testing"
)

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestParseKeyUsages(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []x509.KeyUsage
	}{
		{"empty", nil, nil},
		{"single", []string{"digital-signature"}, []x509.KeyUsage{x509.KeyUsageDigitalSignature}},
		{
			"multiple",
			[]string{"digital-signature", "cert-sign"},
			[]x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign},
		},
		{
			"case and whitespace insensitive",
			[]string{"  DIGITAL-SIGNATURE ", "Cert-Sign"},
			[]x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign},
		},
		{"unknown ignored", []string{"nope"}, nil},
		{"mixed known and unknown", []string{"crl-sign", "bogus"}, []x509.KeyUsage{x509.KeyUsageCRLSign}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseKeyUsages(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseKeyUsages(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseExtKeyUsages(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []x509.ExtKeyUsage
	}{
		{"empty", nil, nil},
		{"single", []string{"server-auth"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{
			"multiple",
			[]string{"server-auth", "client-auth"},
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
		{
			"case and whitespace insensitive",
			[]string{" SERVER-AUTH ", "Client-Auth"},
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
		{"unknown ignored", []string{"nope"}, nil},
		{"any", []string{"any"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseExtKeyUsages(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseExtKeyUsages(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMarshalKeyUsage(t *testing.T) {
	tests := []struct {
		name string
		in   x509.KeyUsage
		want []string
	}{
		{"zero", 0, nil},
		{"single", x509.KeyUsageDigitalSignature, []string{"digital-signature"}},
		{
			"multiple",
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			[]string{"digital-signature", "cert-sign"},
		},
		{
			"all",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			[]string{
				"digital-signature", "content-commitment", "key-encipherment",
				"data-encipherment", "key-agreement", "cert-sign",
				"crl-sign", "encipher-only", "decipher-only",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedCopy(MarshalKeyUsage(tt.in))
			want := sortedCopy(tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("MarshalKeyUsage(%v) = %v, want %v", tt.in, got, want)
			}
		})
	}
}

func TestMarshalExtKeyUsages(t *testing.T) {
	tests := []struct {
		name string
		in   []x509.ExtKeyUsage
		want []string
	}{
		{"empty", nil, nil},
		{"single", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"server-auth"}},
		{
			"multiple preserves order",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			[]string{"server-auth", "client-auth"},
		},
		{
			"unknown skipped",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsage(9999)},
			[]string{"server-auth"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MarshalExtKeyUsages(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("MarshalExtKeyUsages(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseRevocationReason(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"unspecified", "unspecified", 0, false},
		{"key-compromise", "key-compromise", 1, false},
		{"ca-compromise", "ca-compromise", 2, false},
		{"affiliation-changed", "affiliation-changed", 3, false},
		{"superseded", "superseded", 4, false},
		{"cessation-of-operation", "cessation-of-operation", 5, false},
		{"certificate-hold", "certificate-hold", 6, false},
		{"remove-from-crl", "remove-from-crl", 8, false},
		{"privilege-withdrawn", "privilege-withdrawn", 9, false},
		{"a-a-compromise", "a-a-compromise", 10, false},
		{"case and whitespace insensitive", "  KEY-COMPROMISE ", 1, false},
		{"invalid", "bogus", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRevocationReason(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRevocationReason(%q) expected error, got %d", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRevocationReason(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseRevocationReason(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestMarshalRevocationReason(t *testing.T) {
	tests := []struct {
		name    string
		in      int
		want    string
		wantErr bool
	}{
		{"0", 0, "unspecified", false},
		{"1", 1, "key-compromise", false},
		{"2", 2, "ca-compromise", false},
		{"3", 3, "affiliation-changed", false},
		{"4", 4, "superseded", false},
		{"5", 5, "cessation-of-operation", false},
		{"6", 6, "certificate-hold", false},
		{"8", 8, "remove-from-crl", false},
		{"9", 9, "privilege-withdrawn", false},
		{"10", 10, "a-a-compromise", false},
		{"7 is unassigned", 7, "", true},
		{"unknown", 99, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalRevocationReason(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("MarshalRevocationReason(%d) expected error, got %q", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalRevocationReason(%d) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("MarshalRevocationReason(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{"rsa-2048", "rsa-2048", x509.SHA256WithRSA, false},
		{"rsa-4096", "rsa-4096", x509.SHA256WithRSA, false},
		{"ecdsa-224", "ecdsa-224", x509.ECDSAWithSHA1, false},
		{"ecdsa-256", "ecdsa-256", x509.ECDSAWithSHA256, false},
		{"ecdsa-384", "ecdsa-384", x509.ECDSAWithSHA384, false},
		{"ecdsa-521", "ecdsa-521", x509.ECDSAWithSHA512, false},
		{"ed25519", "ed25519", x509.PureEd25519, false},
		{"unknown", "dsa-1024", x509.UnknownSignatureAlgorithm, true},
		{"empty", "", x509.UnknownSignatureAlgorithm, true},
		{"case sensitive", "RSA-2048", x509.UnknownSignatureAlgorithm, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSignatureAlgorithm(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetSignatureAlgorithm(%q) expected error, got %v", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetSignatureAlgorithm(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("GetSignatureAlgorithm(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
