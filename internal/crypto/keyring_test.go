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
	"testing"

	"github.com/zalando/go-keyring"
)

func TestInitAndGetMasterKey(t *testing.T) {
	testService := "pkit-test"
	testAccount := "master-key-test"

	// Override constants for test
	origService := serviceName
	origAccount := accountName
	defer func() {
		serviceName = origService
		accountName = origAccount
		// Clean up test key
		_ = keyring.Delete(testService, testAccount)
	}()
	serviceName = testService
	accountName = testAccount

	// First, delete any existing test key
	_ = keyring.Delete(serviceName, accountName)

	// Test InitMasterKey
	err := InitMasterKey()
	if err != nil {
		t.Fatalf("InitMasterKey failed: %v", err)
	}

	// Test InitMasterKey again (should fail since key already exists)
	err = InitMasterKey()
	if err == nil {
		t.Fatal("InitMasterKey should have failed on second call")
	}

	// Test GetMasterKey
	key, err := GetMasterKey()
	if err != nil {
		t.Fatalf("GetMasterKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("GetMasterKey returned key of length %d, expected 32", len(key))
	}
}
