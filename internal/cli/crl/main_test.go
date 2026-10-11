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

package crl

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/service"
	"github.com/tassok-wasi/pkit/internal/store"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
	"github.com/tassok-wasi/pkit/testutil"
	"github.com/zalando/go-keyring"
)

var (
	testCtx     context.Context
	testDB      *sql.DB
	testQuerier sqlc.Querier
	testSvc     *service.Service
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	if err := crypto.InitMasterKey(); err != nil {
		panic(err)
	}

	var err error
	testDB, err = testutil.InitializeTestDB("crl-test", store.Schema)
	if err != nil {
		panic(err)
	}

	testCtx = context.Background()
	testQuerier = sqlc.New(testDB)
	testSvc = service.New(testDB, testQuerier)

	code := m.Run()
	if err := testDB.Close(); err != nil {
		panic(err)
	}
	os.Exit(code)
}
