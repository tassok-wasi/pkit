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
	"context"
	"database/sql"
	"testing"

	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

func TestRunInTx(t *testing.T) {
	ctx := context.Background()

	// Test 1: Successful transaction
	err := RunInTx(ctx, testDB, func(txQuerier sqlc.Querier) error {
		// Create a test key pair entry
		_, err := txQuerier.CreateKeyPair(ctx, sqlc.CreateKeyPairParams{
			Name:          "test-key",
			Algorithm:     "ecdsa-256",
			PrivateKeyPem: "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----",
			PublicKeyPem:  "-----BEGIN PUBLIC KEY-----\ndummy\n-----END PUBLIC KEY-----",
		})
		return err
	})
	if err != nil {
		t.Fatalf("RunInTx success case failed: %v", err)
	}

	// Verify the key exists
	querier := sqlc.New(testDB)
	key, err := querier.GetKeyByName(ctx, "test-key")
	if err != nil {
		t.Fatalf("key not found after successful tx: %v", err)
	}
	if key.Name != "test-key" {
		t.Fatalf("unexpected key name, got %s", key.Name)
	}

	// Test 2: Rollback on error
	err = RunInTx(ctx, testDB, func(txQuerier sqlc.Querier) error {
		// Create another key
		_, err := txQuerier.CreateKeyPair(ctx, sqlc.CreateKeyPairParams{
			Name:          "rollback-key",
			Algorithm:     "rsa-2048",
			PrivateKeyPem: "dummy",
			PublicKeyPem:  "dummy",
		})
		if err != nil {
			return err
		}
		// Return error to trigger rollback
		return sql.ErrConnDone
	})
	if err == nil {
		t.Fatal("expected error from tx, got nil")
	}

	// Verify key wasn't created
	_, err = querier.GetKeyByName(ctx, "rollback-key")
	if err == nil {
		t.Fatal("rollback-key was found after rollback")
	}

	// Clean up
}
