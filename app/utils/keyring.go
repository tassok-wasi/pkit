package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in Fedora's keyring
func InitMasterKey() error {
	// Check if a key already exists to prevent accidental overwriting
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		return errors.New("application is already initialized with a master key")
	}

	// Generate a secure 32-byte (256-bit) AES key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("cannot generate secure bytes: %w", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	// Save to OS Keyring
	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		return fmt.Errorf("cannot store key in OS keyring: %w", err)
	}
	return nil
}

// GetMasterKey silently retrieves the key from the OS keyring for cryptography
func GetMasterKey() ([]byte, error) {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("app not initialized. Please run the init command first")
		}
		return nil, fmt.Errorf("cannot fetch key from OS keyring: %v", err)
	}

	// Decode back to raw bytes for AES-GCM encryption/decryption
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
