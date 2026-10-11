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
	"reflect"
	"strings"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single value", "alpha", []string{"alpha"}},
		{"multiple values", "alpha,beta,gamma", []string{"alpha", "beta", "gamma"}},
		{"trims surrounding spaces", " alpha , beta , gamma ", []string{"alpha", "beta", "gamma"}},
		{"skips empty segments", "alpha,,beta", []string{"alpha", "beta"}},
		{"skips trailing comma", "alpha,beta,", []string{"alpha", "beta"}},
		{"skips leading comma", ",alpha", []string{"alpha"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitCSV(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SplitCSV(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase", "hello", "hello"},
		{"uppercase", "HELLO", "hello"},
		{"spaces", "Hello World", "hello_world"},
		{"hyphens", "Hello-World", "hello_world"},
		{"underscores preserved as single", "Hello_World", "hello_world"},
		{"mixed separators collapse", "Hello - _ World", "hello_world"},
		{"trims leading and trailing whitespace", "   Hello World   ", "hello_world"},
		{"multiple spaces collapse", "Hello    World", "hello_world"},
		{"other special chars are kept", "Hello!World", "hello!world"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToSnakeCase(tt.in)
			if got != tt.want {
				t.Fatalf("ToSnakeCase(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		fallback string
		want     string
	}{
		{"plain", "report", "fallback", "report"},
		{"keeps allowed chars", "my-file_1.2", "fallback", "my-file_1.2"},
		{"strips path traversal", "../../etc/passwd", "fallback", "etcpasswd"},
		{"strips forward slashes", "a/b/c", "fallback", "abc"},
		{"strips backslashes", `a\b\c`, "fallback", "abc"},
		{"strips disallowed chars", "a@b#c$d", "fallback", "abcd"},
		{"trims whitespace", "   spaced   ", "fallback", "spaced"},
		{"empty falls back", "", "fallback", "fallback"},
		{"dot falls back", ".", "fallback", "fallback"},
		{"double dot falls back", "..", "fallback", "fallback"},
		{"only disallowed falls back", "@#$", "fallback", "fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.input, tt.fallback)
			if got != tt.want {
				t.Fatalf("SanitizeFilename(%q, %q) = %q, want %q", tt.input, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilenameTruncatesLongInput(t *testing.T) {
	long := strings.Repeat("a", 300)
	got := SanitizeFilename(long, "fallback")
	if len(got) != 200 {
		t.Fatalf("expected length 200, got %d", len(got))
	}
	if got != strings.Repeat("a", 200) {
		t.Fatalf("unexpected truncated value: %q", got)
	}
}

func TestParseTTLToHours(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"hours", "1000h", 1000, false},
		{"days", "30d", 720, false},
		{"years", "10y", 87600, false},
		{"single hour", "1h", 1, false},
		{"zero hours", "0h", 0, true},
		{"negative hours", "-5h", 0, true},
		{"unsupported unit", "10m", 0, true},
		{"missing unit", "10", 0, true},
		{"missing number", "h", 0, true},
		{"empty", "", 0, true},
		{"garbage", "abc", 0, true},
		{"decimal", "1.5h", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTTLToHours(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTTLToHours(%q) expected error, got %d", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTTLToHours(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseTTLToHours(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
