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
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeDB(t *testing.T) {
	tmpDir := t.TempDir()

	err := InitializeDB(tmpDir)
	if err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}

	// Verify database file exists
	dbPath := filepath.Join(tmpDir, "pkit.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("db file not created")
	}

	// Try to open it and check schema
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test db failed: %v", err)
	}
	defer db.Close()

	dirInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("stat db dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("db directory permissions = %o, want 700", dirInfo.Mode().Perm())
	}
	dbInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if dbInfo.Mode().Perm() != 0o600 {
		t.Fatalf("db file permissions = %o, want 600", dbInfo.Mode().Perm())
	}

	conn, err := GetConnection(dbPath)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	defer conn.Close()
	var version int
	if err := conn.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, SchemaVersion)
	}

	// Verify tables are present
	tables := []string{"keys", "certificates", "csrs", "crls"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s not found: %v", table, err)
		}
	}
}
