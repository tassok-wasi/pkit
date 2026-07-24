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

package db

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
