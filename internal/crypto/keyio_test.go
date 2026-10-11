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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strconv"
	"strings"
	"testing"
	"time"
)

// requireMasterKey skips a test when the OS keyring (and therefore the master
// key) is not available in the current environment.
func requireMasterKey(t *testing.T) {
	t.Helper()
	if _, err := GetMasterKey(); err != nil {
		t.Skipf("master key unavailable, skipping: %v", err)
	}
}

func TestGenerateKeyName(t *testing.T) {
	before := time.Now().Unix()
	name := GenerateKeyName("mykey")
	after := time.Now().Unix()

	if !strings.HasPrefix(name, "mykey-") {
		t.Fatalf("expected prefix %q, got %q", "mykey-", name)
	}

	suffix := strings.TrimPrefix(name, "mykey-")
	ts, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil {
		t.Fatalf("suffix %q is not a valid integer: %v", suffix, err)
	}
	if ts < before || ts > after {
		t.Fatalf("timestamp %d not in range [%d, %d]", ts, before, after)
	}
}

func TestMarshalKeysRoundTrip(t *testing.T) {
	requireMasterKey(t)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	privPem, pubPem, err := MarshalKeys(priv, &priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalKeys error: %v", err)
	}
	if len(privPem) == 0 || len(pubPem) == 0 {
		t.Fatal("expected non-empty PEM output")
	}

	gotPriv, gotPub, err := ParseKeys(privPem, pubPem)
	if err != nil {
		t.Fatalf("ParseKeys error: %v", err)
	}

	rsaPriv, ok := gotPriv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", gotPriv)
	}
	if !rsaPriv.Equal(priv) {
		t.Fatal("decrypted private key does not match original")
	}

	rsaPub, ok := gotPub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", gotPub)
	}
	if !rsaPub.Equal(&priv.PublicKey) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestReturnPrivPubPemRoundTrip(t *testing.T) {
	requireMasterKey(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	privPem, pubPem, err := ReturnPrivPubPem(priv, pub)
	if err != nil {
		t.Fatalf("ReturnPrivPubPem error: %v", err)
	}

	decrypted, err := DecryptPrivateKey(privPem)
	if err != nil {
		t.Fatalf("DecryptPrivateKey error: %v", err)
	}
	parsedPriv, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("failed to parse decrypted private key: %v", err)
	}
	edPriv, ok := parsedPriv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsedPriv)
	}
	if !edPriv.Equal(priv) {
		t.Fatal("decrypted private key does not match original")
	}

	pubBytes, err := DecodeToPem(pubPem)
	if err != nil {
		t.Fatalf("DecodeToPem error: %v", err)
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	edPub, ok := parsedPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", parsedPub)
	}
	if !edPub.Equal(pub) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestEncryptDecryptPrivateKeyRoundTrip(t *testing.T) {
	requireMasterKey(t)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encrypted, err := EncryptPrivateKey(priv)
	if err != nil {
		t.Fatalf("EncryptPrivateKey error: %v", err)
	}

	pemBytes, err := EncodeToPem(encrypted, "PRIVATE KEY")
	if err != nil {
		t.Fatalf("EncodeToPem error: %v", err)
	}

	decrypted, err := DecryptPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("DecryptPrivateKey error: %v", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("failed to parse decrypted key: %v", err)
	}
	ecPriv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	if !ecPriv.Equal(priv) {
		t.Fatal("decrypted private key does not match original")
	}
}

func TestDecryptPrivateKeyInvalidPEM(t *testing.T) {
	// Decoding fails before the master key is needed, so no skip guard here.
	if _, err := DecryptPrivateKey([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid PEM input")
	}
}

func TestEncryptPrivateKeyInvalidKey(t *testing.T) {
	if _, err := EncryptPrivateKey("not-a-key"); err == nil {
		t.Fatal("expected error for non-marshalable key")
	}
}
