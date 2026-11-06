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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

var ciphertextVersion = []byte("PKIT1")

func Encrypt(plaintext, masterKey, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to generate gcm AEAD: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate secure nonce: %w", err)
	}

	ciphertext := append(append([]byte{}, ciphertextVersion...), nonce...)
	return aesGCM.Seal(ciphertext, nonce, plaintext, aad), nil
}

func Decrypt(ciphertext, masterKey, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to generate gcm AEAD: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < len(ciphertextVersion)+nonceSize {
		return nil, fmt.Errorf("cipher is too short: %v", len(ciphertext))
	}
	if !bytes.Equal(ciphertext[:len(ciphertextVersion)], ciphertextVersion) {
		return nil, fmt.Errorf("unsupported ciphertext version")
	}

	body := ciphertext[len(ciphertextVersion):]
	nonce, actualCiphertext := body[:nonceSize], body[nonceSize:]
	return aesGCM.Open(nil, nonce, actualCiphertext, aad)
}
