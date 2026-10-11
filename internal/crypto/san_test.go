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
	"net"
	"net/url"
	"testing"
)

func TestToNetIP(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"ipv4", "192.168.1.1", "192.168.1.1", false},
		{"ipv4 loopback", "127.0.0.1", "127.0.0.1", false},
		{"ipv6", "2001:db8::1", "2001:db8::1", false},
		{"ipv6 loopback", "::1", "::1", false},
		{"empty", "", "", true},
		{"hostname", "example.com", "", true},
		{"invalid", "999.999.999.999", "", true},
		{"garbage", "not-an-ip", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToNetIP(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ToNetIP(%q) expected error, got %v", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToNetIP(%q) unexpected error: %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ToNetIP(%q) = %q, want %q", tt.in, got.String(), tt.want)
			}
		})
	}
}

func TestToNetIPs(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		got, err := ToNetIPs([]string{"192.168.1.1", "2001:db8::1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")}
		if !IpSlicesEqual(got, want) {
			t.Fatalf("ToNetIPs mismatch: got %v, want %v", got, want)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		got, err := ToNetIPs(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty result, got %v", got)
		}
	})

	t.Run("invalid element", func(t *testing.T) {
		if _, err := ToNetIPs([]string{"192.168.1.1", "bad"}); err == nil {
			t.Fatal("expected error for invalid element")
		}
	})
}

func TestToURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"https", "https://example.com/path", "https://example.com/path", false},
		{"http with port", "http://example.com:8080", "http://example.com:8080", false},
		{"trims whitespace", "  https://example.com  ", "https://example.com", false},
		{"missing scheme", "example.com/path", "", true},
		{"missing host", "mailto:foo@example.com", "", true},
		{"user info rejected", "https://user:pass@example.com", "", true},
		{"empty", "", "", true},
		{"invalid", "://bad", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToURL(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ToURL(%q) expected error, got %v", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToURL(%q) unexpected error: %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ToURL(%q) = %q, want %q", tt.in, got.String(), tt.want)
			}
		})
	}
}

func TestToURLs(t *testing.T) {
	t.Run("valid list", func(t *testing.T) {
		got, err := ToURLs([]string{"https://a.example.com", "https://b.example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []*url.URL{
			{Scheme: "https", Host: "a.example.com"},
			{Scheme: "https", Host: "b.example.com"},
		}
		if !UriSlicesEqual(got, want) {
			t.Fatalf("ToURLs mismatch: got %v, want %v", got, want)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		got, err := ToURLs(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty result, got %v", got)
		}
	})

	t.Run("invalid element", func(t *testing.T) {
		if _, err := ToURLs([]string{"https://a.example.com", "bad"}); err == nil {
			t.Fatal("expected error for invalid element")
		}
	})
}

func TestIpSlicesEqual(t *testing.T) {
	a := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
	b := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
	c := []net.IP{net.ParseIP("192.168.1.1")}
	d := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.2")}

	if !IpSlicesEqual(a, b) {
		t.Fatal("expected equal slices")
	}
	if IpSlicesEqual(a, c) {
		t.Fatal("expected unequal slices for different lengths")
	}
	if IpSlicesEqual(a, d) {
		t.Fatal("expected unequal slices for different values")
	}
	if !IpSlicesEqual(nil, nil) {
		t.Fatal("expected nil slices to be equal")
	}
}

func TestFormatIPs(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")}
	got := FormatIPs(ips)
	want := "192.168.1.1, 2001:db8::1"
	if got != want {
		t.Fatalf("FormatIPs = %q, want %q", got, want)
	}

	if got := FormatIPs(nil); got != "" {
		t.Fatalf("FormatIPs(nil) = %q, want empty", got)
	}
}

func TestUriSlicesEqual(t *testing.T) {
	a := []*url.URL{{Scheme: "https", Host: "a.example.com"}}
	b := []*url.URL{{Scheme: "https", Host: "a.example.com"}}
	c := []*url.URL{{Scheme: "https", Host: "b.example.com"}}
	d := []*url.URL{
		{Scheme: "https", Host: "a.example.com"},
		{Scheme: "https", Host: "b.example.com"},
	}

	if !UriSlicesEqual(a, b) {
		t.Fatal("expected equal slices")
	}
	if UriSlicesEqual(a, c) {
		t.Fatal("expected unequal slices for different values")
	}
	if UriSlicesEqual(a, d) {
		t.Fatal("expected unequal slices for different lengths")
	}
	if !UriSlicesEqual(nil, nil) {
		t.Fatal("expected nil slices to be equal")
	}
}

func TestFormatURIs(t *testing.T) {
	uris := []*url.URL{
		{Scheme: "https", Host: "a.example.com"},
		{Scheme: "https", Host: "b.example.com"},
	}
	got := FormatURIs(uris)
	want := "https://a.example.com, https://b.example.com"
	if got != want {
		t.Fatalf("FormatURIs = %q, want %q", got, want)
	}

	if got := FormatURIs(nil); got != "" {
		t.Fatalf("FormatURIs(nil) = %q, want empty", got)
	}
}
