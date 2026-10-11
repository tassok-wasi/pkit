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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// JoinHomeDir expands a leading "~/" into the user's home directory.
func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

// ResolveDestinationPath resolves a user-supplied output path into a concrete file path.
func ResolveDestinationPath(inputPath, defaultName, defaultExt string) (string, error) {
	defaultFilename := SanitizeFilename(strings.ToLower(defaultName), "exported_item") + defaultExt
	if inputPath == "" {
		return defaultFilename, nil
	}

	resolvedPath, err := JoinHomeDir(inputPath)
	if err != nil {
		return "", err
	}

	if fi, err := os.Stat(resolvedPath); err == nil {
		if fi.IsDir() {
			return filepath.Join(resolvedPath, defaultFilename), nil
		}
		return resolvedPath, nil
	}

	if strings.HasSuffix(inputPath, "/") || strings.HasSuffix(inputPath, "\\") || filepath.Ext(resolvedPath) == "" {
		return filepath.Join(resolvedPath, defaultFilename), nil
	}

	return resolvedPath, nil
}

// ReadFile reads a file, expanding a leading "~/" in the path.
func ReadFile(path string) ([]byte, error) {
	fullPath, err := JoinHomeDir(path)
	if err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return bytes, nil
}
