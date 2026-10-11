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

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/store/sqlc"
)

// GenerateKeyRequest describes a key pair to generate.
type GenerateKeyRequest struct {
	KeyType string
	Name    string
}

// ListKeysRequest paginates a key listing.
type ListKeysRequest struct {
	Limit  int
	Offset int
}

// KeySummary is a normalized row for listing key pairs.
type KeySummary struct {
	ID        int64
	Name      string
	Algorithm string
	CreatedAt time.Time
}

// ExportKeyRequest describes a key pair export to disk.
type ExportKeyRequest struct {
	ID     int64
	Path   string
	Format string
	Blob   bool
}

// GenerateKey creates a new key pair and persists it.
func (s *Service) GenerateKey(ctx context.Context, req GenerateKeyRequest) (sqlc.Key, error) {
	keyPair, err := pki.GetKey(pki.KeyType(req.KeyType))
	if err != nil {
		return sqlc.Key{}, err
	}

	privBlobPem, pubPem, err := crypto.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return sqlc.Key{}, err
	}

	return s.q.CreateKeyPair(ctx, sqlc.CreateKeyPairParams{
		Name:          req.Name,
		Algorithm:     req.KeyType,
		PrivateKeyPem: string(privBlobPem),
		PublicKeyPem:  string(pubPem),
	})
}

// ListKeys returns key pairs matching the given pagination.
func (s *Service) ListKeys(ctx context.Context, req ListKeysRequest) ([]KeySummary, error) {
	var summaries []KeySummary

	if req.Limit == 0 && req.Offset == 0 {
		keys, err := s.q.ListAllKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch keys from DB: %w", err)
		}
		for _, k := range keys {
			summaries = append(summaries, KeySummary{ID: k.ID, Name: k.Name, Algorithm: k.Algorithm, CreatedAt: k.CreatedAt.Time})
		}
		return summaries, nil
	}

	keys, err := s.q.ListKeys(ctx, sqlc.ListKeysParams{
		Limit:  int64(req.Limit),
		Offset: int64(req.Offset),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys from DB: %w", err)
	}
	for _, k := range keys {
		summaries = append(summaries, KeySummary{ID: k.ID, Name: k.Name, Algorithm: k.Algorithm, CreatedAt: k.CreatedAt.Time})
	}
	return summaries, nil
}

// GetKey returns the raw stored record for a key pair.
func (s *Service) GetKey(ctx context.Context, id int64) (sqlc.Key, error) {
	rec, err := s.q.GetKeyByID(ctx, id)
	if err != nil {
		return sqlc.Key{}, fmt.Errorf("failed to fetch key from DB: %w", err)
	}
	return rec, nil
}

// GetParsedKey returns the decrypted private key and public key for a record.
func (s *Service) GetParsedKey(ctx context.Context, id int64) (privateKey any, publicKey any, err error) {
	rec, err := s.q.GetKeyByID(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch key from DB: %w", err)
	}
	return parseKeyRecord(rec)
}

// ReadKey returns the decrypted private key and public key as PEM strings.
func (s *Service) ReadKey(ctx context.Context, id int64) (privateKeyPEM, publicKeyPEM string, err error) {
	rec, err := s.q.GetKeyByID(ctx, id)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	decrypted, err := crypto.DecryptPrivateKey([]byte(rec.PrivateKeyPem))
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt private key: %w", err)
	}

	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: decrypted,
	}))

	return privateKeyPEM, rec.PublicKeyPem, nil
}

// VerifyKey checks that a certificate's public key matches its stored private key.
func (s *Service) VerifyKey(ctx context.Context, id int64) error {
	dbCert, err := s.getCertificateRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	cert, err := parseCertificateRecord(dbCert)
	if err != nil {
		return err
	}

	key, err := s.q.GetKeyByID(ctx, dbCert.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}
	privateKey, _, err := parseKeyRecord(key)
	if err != nil {
		return err
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an RSA public key, but the private key is not RSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: RSA private key does not belong to this certificate")
		}

	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an ECDSA public key, but the private key is not ECDSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: ECDSA private key does not belong to this certificate")
		}

	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an Ed25519 public key, but the private key is not Ed25519")
		}
		privPub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || !pub.Equal(privPub) {
			return errors.New("cryptographic mismatch: Ed25519 private key does not belong to this certificate")
		}

	default:
		return fmt.Errorf("unsupported public key algorithm type: %T", cert.PublicKey)
	}

	return nil
}

// RenameKey updates the friendly name of a key pair.
func (s *Service) RenameKey(ctx context.Context, id int64, name string) error {
	newName := strings.TrimSpace(name)
	if newName == "" {
		return fmt.Errorf("new key name cannot be empty")
	}

	if _, err := s.q.GetKeyByID(ctx, id); err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	if _, err := s.q.UpdateKeyName(ctx, sqlc.UpdateKeyNameParams{ID: id, Name: newName}); err != nil {
		return fmt.Errorf("failed to rename key in DB: %w", err)
	}

	return nil
}

// DeleteKey removes a key pair from the database.
func (s *Service) DeleteKey(ctx context.Context, id int64) error {
	if _, err := s.q.GetKeyByID(ctx, id); err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}
	if err := s.q.DeleteKeyByID(ctx, id); err != nil {
		return fmt.Errorf("failed to delete key from DB: %w", err)
	}
	return nil
}

// ExportKey writes the private and public key to disk and returns both paths.
func (s *Service) ExportKey(ctx context.Context, req ExportKeyRequest) (string, string, error) {
	key, err := s.q.GetKeyByID(ctx, req.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "pem"
	}

	ext := ".pem"
	if format == "der" {
		ext = ".der"
	} else if format != "pem" {
		return "", "", fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", req.Format)
	}

	privKeyFilePath, pubKeyFilePath, err := resolveKeyDestinationPaths(req.Path, key.Name, ext)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve output path: %w", err)
	}

	var privBytes, pubBytes []byte

	if format == "pem" {
		if !req.Blob {
			decryptedPrivKey, err := crypto.DecryptPrivateKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return "", "", fmt.Errorf("failed to decrypt private key: %w", err)
			}
			privBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: decryptedPrivKey,
			})
		} else {
			privBytes = []byte(key.PrivateKeyPem)
		}
		pubBytes = []byte(key.PublicKeyPem)
	} else {
		if !req.Blob {
			decryptedPrivKey, err := crypto.DecryptPrivateKey([]byte(key.PrivateKeyPem))
			if err != nil {
				return "", "", fmt.Errorf("failed to decrypt private key: %w", err)
			}
			privBytes = decryptedPrivKey
		} else {
			privBlock, _ := pem.Decode([]byte(key.PrivateKeyPem))
			if privBlock == nil {
				return "", "", errors.New("failed to decode private key PEM into DER")
			}
			privBytes = privBlock.Bytes
		}

		pubBlock, _ := pem.Decode([]byte(key.PublicKeyPem))
		if pubBlock == nil {
			return "", "", errors.New("failed to decode public key PEM into DER")
		}
		pubBytes = pubBlock.Bytes
	}

	if err := writeFile(privKeyFilePath, privBytes, 0o600); err != nil {
		return "", "", err
	}
	if err := writeFile(pubKeyFilePath, pubBytes, 0o644); err != nil {
		return "", "", err
	}

	return privKeyFilePath, pubKeyFilePath, nil
}

// resolveKeyDestinationPaths calculates output file paths for a key pair.
func resolveKeyDestinationPaths(inputPath, keyName, ext string) (string, string, error) {
	sanitizedBase := crypto.ToSnakeCase(crypto.SanitizeFilename(keyName, "exported_key"))

	if inputPath == "" {
		privPath := sanitizedBase + "_private_key" + ext
		pubPath := sanitizedBase + "_public_key" + ext
		return privPath, pubPath, nil
	}

	resolvedPath, err := crypto.JoinHomeDir(inputPath)
	if err != nil {
		return "", "", err
	}

	fi, err := os.Stat(resolvedPath)
	isDir := err == nil && fi.IsDir()

	if isDir || strings.HasSuffix(inputPath, "/") || strings.HasSuffix(inputPath, "\\") || filepath.Ext(resolvedPath) == "" {
		privPath := filepath.Join(resolvedPath, sanitizedBase+"_private_key"+ext)
		pubPath := filepath.Join(resolvedPath, sanitizedBase+"_public_key"+ext)
		return privPath, pubPath, nil
	}

	dir := filepath.Dir(resolvedPath)
	baseName := filepath.Base(resolvedPath)

	if pathExt := filepath.Ext(baseName); pathExt != "" {
		baseName = strings.TrimSuffix(baseName, pathExt)
	}

	privPath := filepath.Join(dir, baseName+"_private_key"+ext)
	pubPath := filepath.Join(dir, baseName+"_public_key"+ext)

	return privPath, pubPath, nil
}
