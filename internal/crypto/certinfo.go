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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// GetSerialNumber generates a random 128-bit certificate serial number.
func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return sNum, nil
}

// GetKeyDetails returns a human-readable algorithm name and size for a key.
func GetKeyDetails(key any) (algoType string, sizeInfo string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		algoType = "RSA Private Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PrivateKey:
		algoType = "ECDSA Private Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PrivateKey:
		algoType = "Ed25519 Private Key"
		sizeInfo = "256-bit seed"
	case *rsa.PublicKey:
		algoType = "RSA Public Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PublicKey:
		algoType = "ECDSA Public Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PublicKey:
		algoType = "Ed25519 Public Key"
		sizeInfo = "256-bit"
	default:
		algoType = fmt.Sprintf("Unknown (%T)", key)
		sizeInfo = "N/A"
	}
	return algoType, sizeInfo
}

// TruncateHex renders the first 16 bytes of a byte slice as hex.
func TruncateHex(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	fullHex := hex.EncodeToString(b)
	if len(fullHex) > 32 {
		return fullHex[:32]
	}
	return fullHex
}

// FormatFingerprint formats a byte slice fingerprint into standard double-spaced format (e.g., "AA:BB:CC:...").
func FormatFingerprint(b []byte) string {
	var parts []string
	for _, val := range b {
		parts = append(parts, fmt.Sprintf("%02X", val))
	}
	return strings.Join(parts, ":")
}

// Structural definition for parsing RFC 5280 Authority Key Identifier
type authKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"optional,tag:0"`
}

// ExtractAuthorityKeyID extracts the raw AKID bytes from a certificate extensions block.
func ExtractAuthorityKeyID(cert *x509.Certificate) ([]byte, error) {
	// OID 2.5.29.35 represents Authority Key Identifier
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 35}) {
			var akid authKeyIdentifier
			_, err := asn1.Unmarshal(ext.Value, &akid)
			if err != nil {
				return nil, err
			}
			return akid.KeyIdentifier, nil
		}
	}
	return nil, fmt.Errorf("authority key identifier extension not found")
}

// IsSelfSigned checks if a certificate's subject matches its issuer (Self-signed Root CA check).
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}
