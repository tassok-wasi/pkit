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
	"errors"
	"fmt"
	"strings"
)

// ParseKeyUsages maps CLI strings to x509.KeyUsage flags.
func ParseKeyUsages(usages []string) []x509.KeyUsage {
	var out []x509.KeyUsage
	m := map[string]x509.KeyUsage{
		"digital-signature":  x509.KeyUsageDigitalSignature,
		"content-commitment": x509.KeyUsageContentCommitment,
		"key-encipherment":   x509.KeyUsageKeyEncipherment,
		"data-encipherment":  x509.KeyUsageDataEncipherment,
		"key-agreement":      x509.KeyUsageKeyAgreement,
		"cert-sign":          x509.KeyUsageCertSign,
		"crl-sign":           x509.KeyUsageCRLSign,
		"encipher-only":      x509.KeyUsageEncipherOnly,
		"decipher-only":      x509.KeyUsageDecipherOnly,
	}
	for _, u := range usages {
		if ku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, ku)
		}
	}
	return out
}

// ParseExtKeyUsages maps CLI strings to x509.ExtKeyUsage flags.
func ParseExtKeyUsages(usages []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	m := map[string]x509.ExtKeyUsage{
		"any":              x509.ExtKeyUsageAny,
		"server-auth":      x509.ExtKeyUsageServerAuth,
		"client-auth":      x509.ExtKeyUsageClientAuth,
		"code-signing":     x509.ExtKeyUsageCodeSigning,
		"email-protection": x509.ExtKeyUsageEmailProtection,
		"time-stamping":    x509.ExtKeyUsageTimeStamping,
		"ocsp-signing":     x509.ExtKeyUsageOCSPSigning,
	}
	for _, u := range usages {
		if eku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, eku)
		}
	}
	return out
}

// MarshalKeyUsage converts x509.KeyUsage flags back to their CLI strings.
func MarshalKeyUsage(usage x509.KeyUsage) []string {
	var out []string
	m := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "digital-signature",
		x509.KeyUsageContentCommitment: "content-commitment",
		x509.KeyUsageKeyEncipherment:   "key-encipherment",
		x509.KeyUsageDataEncipherment:  "data-encipherment",
		x509.KeyUsageKeyAgreement:      "key-agreement",
		x509.KeyUsageCertSign:          "cert-sign",
		x509.KeyUsageCRLSign:           "crl-sign",
		x509.KeyUsageEncipherOnly:      "encipher-only",
		x509.KeyUsageDecipherOnly:      "decipher-only",
	}

	for ku, name := range m {
		if usage&ku > 0 {
			out = append(out, name)
		}
	}
	return out
}

// MarshalExtKeyUsages converts x509.ExtKeyUsage flags back to their CLI strings.
func MarshalExtKeyUsages(extUsages []x509.ExtKeyUsage) []string {
	var out []string
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "server-auth",
		x509.ExtKeyUsageClientAuth:      "client-auth",
		x509.ExtKeyUsageCodeSigning:     "code-signing",
		x509.ExtKeyUsageEmailProtection: "email-protection",
		x509.ExtKeyUsageTimeStamping:    "time-stamping",
		x509.ExtKeyUsageOCSPSigning:     "ocsp-signing",
	}

	for _, eku := range extUsages {
		if name, exists := m[eku]; exists {
			out = append(out, name)
		}
	}
	return out
}

// ParseRevocationReason maps a single string input to an RFC 5280 integer code.
func ParseRevocationReason(reason string) (int, error) {
	m := map[string]int{
		"unspecified":            0,
		"key-compromise":         1,
		"ca-compromise":          2,
		"affiliation-changed":    3,
		"superseded":             4,
		"cessation-of-operation": 5,
		"certificate-hold":       6,
		"remove-from-crl":        8,
		"privilege-withdrawn":    9,
		"a-a-compromise":         10,
	}

	cleaned := strings.ToLower(strings.TrimSpace(reason))
	if code, exists := m[cleaned]; exists {
		return code, nil
	}

	return 0, errors.New("invalid revocation reason: " + reason)
}

// MarshalRevocationReason converts a single integer code back to its string representation.
func MarshalRevocationReason(code int) (string, error) {
	m := map[int]string{
		0:  "unspecified",
		1:  "key-compromise",
		2:  "ca-compromise",
		3:  "affiliation-changed",
		4:  "superseded",
		5:  "cessation-of-operation",
		6:  "certificate-hold",
		8:  "remove-from-crl",
		9:  "privilege-withdrawn",
		10: "a-a-compromise",
	}

	if name, exists := m[code]; exists {
		return name, nil
	}

	return "", errors.New("unknown revocation code")
}

// GetSignatureAlgorithm maps a CLI string input to the correct x509 SignatureAlgorithm.
func GetSignatureAlgorithm(keyType string) (x509.SignatureAlgorithm, error) {
	switch keyType {
	case "rsa-2048", "rsa-4096":
		return x509.SHA256WithRSA, nil
	case "ecdsa-224":
		return x509.ECDSAWithSHA1, nil // SHA1 is standard for P-224, but consider upgrading keyType if security allows
	case "ecdsa-256":
		return x509.ECDSAWithSHA256, nil
	case "ecdsa-384":
		return x509.ECDSAWithSHA384, nil
	case "ecdsa-521":
		return x509.ECDSAWithSHA512, nil
	case "ed25519":
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported or invalid key type: %s", keyType)
	}
}
