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
	"encoding/pem"
	"errors"
	"fmt"
)

// EncodeToPem wraps raw DER bytes in a PEM block of the given type.
func EncodeToPem(bytes []byte, blockType string) ([]byte, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})

	if pemBytes == nil {
		return nil, errors.New("failed to encode to pem")
	}

	return pemBytes, nil
}

// DecodeToPem extracts the DER bytes from a PEM block.
func DecodeToPem(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return block.Bytes, nil
}

// MarshalCertificate encodes an X.509 certificate as PEM.
func MarshalCertificate(cert *x509.Certificate) ([]byte, error) {
	certBytes := cert.Raw

	certPem, err := EncodeToPem(certBytes, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return []byte(certPem), nil
}

// ParseCertificate parses a PEM-encoded X.509 certificate.
func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	certBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Certificate: %w", err)
	}
	return cert, nil
}

// ParseCRL parses a PEM-encoded X.509 revocation list.
func ParseCRL(pemBytes []byte) (*x509.RevocationList, error) {
	crlBytes, err := DecodeToPem(pemBytes)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Revocation List: %w", err)
	}
	return crl, nil
}

// ParseCSR parses a PEM-encoded certificate signing request.
func ParseCSR(pemStr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM format")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
