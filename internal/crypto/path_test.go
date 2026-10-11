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
	"os"
	"path/filepath"
	"testing"
)

func TestJoinHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}

	t.Run("expands tilde prefix", func(t *testing.T) {
		got, err := JoinHomeDir("~/certs/root.pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(home, "certs/root.pem")
		if got != want {
			t.Fatalf("JoinHomeDir = %q, want %q", got, want)
		}
	})

	t.Run("leaves absolute path untouched", func(t *testing.T) {
		in := "/var/lib/certs/root.pem"
		got, err := JoinHomeDir(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != in {
			t.Fatalf("JoinHomeDir = %q, want %q", got, in)
		}
	})

	t.Run("leaves bare tilde untouched", func(t *testing.T) {
		got, err := JoinHomeDir("~")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "~" {
			t.Fatalf("JoinHomeDir = %q, want %q", got, "~")
		}
	})

	t.Run("leaves relative path untouched", func(t *testing.T) {
		got, err := JoinHomeDir("certs/root.pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "certs/root.pem" {
			t.Fatalf("JoinHomeDir = %q, want %q", got, "certs/root.pem")
		}
	})
}

func TestResolveDestinationPath(t *testing.T) {
	t.Run("empty input uses default filename", func(t *testing.T) {
		got, err := ResolveDestinationPath("", "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "mycert.pem" {
			t.Fatalf("got %q, want %q", got, "mycert.pem")
		}
	})

	t.Run("existing directory joins default filename", func(t *testing.T) {
		dir := t.TempDir()
		got, err := ResolveDestinationPath(dir, "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(dir, "mycert.pem")
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("existing file is returned as-is", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "existing.pem")
		if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		got, err := ResolveDestinationPath(file, "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != file {
			t.Fatalf("got %q, want %q", got, file)
		}
	})

	t.Run("trailing slash treated as directory", func(t *testing.T) {
		dir := t.TempDir()
		in := dir + string(os.PathSeparator)
		got, err := ResolveDestinationPath(in, "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(dir, "mycert.pem")
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("path without extension treated as directory", func(t *testing.T) {
		dir := t.TempDir()
		in := filepath.Join(dir, "subdir")
		got, err := ResolveDestinationPath(in, "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(in, "mycert.pem")
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("path with extension returned as-is", func(t *testing.T) {
		dir := t.TempDir()
		in := filepath.Join(dir, "output.pem")
		got, err := ResolveDestinationPath(in, "MyCert", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != in {
			t.Fatalf("got %q, want %q", got, in)
		}
	})

	t.Run("empty default name falls back", func(t *testing.T) {
		got, err := ResolveDestinationPath("", "", ".pem")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "exported_item.pem" {
			t.Fatalf("got %q, want %q", got, "exported_item.pem")
		}
	})
}

func TestReadFile(t *testing.T) {
	t.Run("reads existing file", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "data.txt")
		want := []byte("hello world")
		if err := os.WriteFile(file, want, 0o600); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}

		got, err := ReadFile(file)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := ReadFile(filepath.Join(dir, "does-not-exist.txt")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}
