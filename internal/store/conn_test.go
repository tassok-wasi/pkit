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

package store

import (
	"path/filepath"
	"testing"
)

func TestGetConnection(t *testing.T) {
	// Test 1: Non-existent DB (should return error)
	nonExistent := "/tmp/non-existent-pkit.db"
	_, err := GetConnection(nonExistent)
	if err == nil {
		t.Fatalf("expected error for non-existent DB, got nil")
	}

	// Test 2: Create a temporary DB first, then try to get connection
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkit.db")

	// Initialize a minimal initialization of the test DB first
	err = InitializeDB(tmpDir)
	if err != nil {
		t.Fatalf("failed to init DB: %v", err)
	}

	db, err := GetConnection(dbPath)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	defer db.Close()

	// Test if the connection is alive
	if err := db.Ping(); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}
