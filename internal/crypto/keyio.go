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
	"crypto/x509"
	"fmt"
	"time"
)

// ReturnPrivPubPem marshals a key pair into an encrypted private key PEM and a
// public key PEM.
func ReturnPrivPubPem(privateKey any, publicKey any) ([]byte, []byte, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get master key from os keyring: %w", err)
	}
	privBytesBlob, err := Encrypt(privBytes, masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	privBlobPem, err := EncodeToPem(privBytesBlob, "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPem, err := EncodeToPem(pubBytes, "PUBLIC KEY")
	if err != nil {
		return nil, nil, err
	}

	return privBlobPem, pubPem, nil
}

// MarshalKeys marshals a key pair into an encrypted private key PEM and a
// public key PEM.
func MarshalKeys(privKey, pubKey any) ([]byte, []byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	privBlobBytes, err := EncryptPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	privPem, err := EncodeToPem(privBlobBytes, "PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	pubPem, err := EncodeToPem(pubBytes, "PUBLIC KEY")
	if err != nil {
		return nil, nil, err
	}

	return privPem, pubPem, nil
}

// ParseKeys decrypts and parses a stored private key PEM and public key PEM.
func ParseKeys(privPem []byte, pubPem []byte) (any, any, error) {
	decryptedPrivKey, err := DecryptPrivateKey(privPem)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := DecodeToPem(pubPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// EncryptPrivateKey marshals and encrypts a private key using the master key.
func EncryptPrivateKey(priv any) ([]byte, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := Encrypt(privBytes, masterKey)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}

// DecryptPrivateKey decrypts an encrypted private key PEM using the master key.
func DecryptPrivateKey(privPem []byte) ([]byte, error) {
	privKey, err := DecodeToPem(privPem)
	if err != nil {
		return nil, err
	}

	masterKey, err := GetMasterKey()
	if err != nil {
		return nil, err
	}

	decryptedPrivKey, err := Decrypt(privKey, masterKey)
	if err != nil {
		return nil, err
	}

	return decryptedPrivKey, nil
}

// GenerateKeyName appends a Unix timestamp to the common name.
func GenerateKeyName(commonName string) string {
	return fmt.Sprintf("%s-%d", commonName, time.Now().Unix())
}
