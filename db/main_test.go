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
	"testing"

	"pkit/testutil"
)

// testDB will hold our in-memory database connection for all db package tests
var testDB *sql.DB

func TestMain(m *testing.M) {
	var err error
	testDB, err = testutil.InitializeTestDB("pkit-test", Schema)
	if err != nil {
		panic(err)
	}

	// Run the tests
	code := m.Run()

	// Cleanup
	if err := testDB.Close(); err != nil {
		panic(err)
	}

	os.Exit(code)
}
