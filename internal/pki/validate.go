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

package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// ValidationResult holds the outcome of a structural/policy sanity check.
type ValidationResult struct {
	Issues   []string
	Warnings []string
}

// ValidateCertificate performs sanity and policy checks on an X.509 certificate.
func ValidateCertificate(cert *x509.Certificate) ValidationResult {
	var res ValidationResult

	now := time.Now()
	if now.Before(cert.NotBefore) {
		res.Issues = append(res.Issues, fmt.Sprintf("Not active yet (Valid starting: %s)", cert.NotBefore.Format("2006-01-02 15:04:05 UTC")))
	} else if now.After(cert.NotAfter) {
		res.Issues = append(res.Issues, fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02 15:04:05 UTC")))
	} else {
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysRemaining <= 30 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Certificate expires soon (%d days remaining)", daysRemaining))
		}
	}

	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		res.Issues = append(res.Issues, fmt.Sprintf("Insecure signature algorithm used: %s", cert.SignatureAlgorithm))
	}

	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keySize := rsaKey.N.BitLen()
		if keySize < 2048 {
			res.Issues = append(res.Issues, fmt.Sprintf("Weak RSA key length (%d bits; minimum required is 2048 bits)", keySize))
		}
	}

	if !cert.IsCA && len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		res.Warnings = append(res.Warnings, "Certificate lacks SANs (DNSNames/IPAddresses); modern browsers require SAN entries")
	}

	return res
}

// ValidateCRL performs sanity and validity period checks on a revocation list.
func ValidateCRL(crl *x509.RevocationList) ValidationResult {
	var res ValidationResult

	now := time.Now()

	if now.Before(crl.ThisUpdate) {
		res.Issues = append(res.Issues, fmt.Sprintf("CRL 'ThisUpdate' is in the future (Valid starting: %s)", crl.ThisUpdate.Format("2006-01-02 15:04:05 UTC")))
	}

	if !crl.NextUpdate.IsZero() {
		if now.After(crl.NextUpdate) {
			res.Issues = append(res.Issues, fmt.Sprintf("CRL expired on %s", crl.NextUpdate.Format("2006-01-02 15:04:05 UTC")))
		} else {
			hoursRemaining := time.Until(crl.NextUpdate).Hours()
			if hoursRemaining <= 24 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("CRL expires soon (%.1f hours remaining)", hoursRemaining))
			}
		}
	} else {
		res.Warnings = append(res.Warnings, "CRL lacks a 'NextUpdate' field; expiration bounds cannot be enforced automatically")
	}

	switch crl.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		res.Issues = append(res.Issues, fmt.Sprintf("Insecure signature algorithm used for CRL: %s", crl.SignatureAlgorithm))
	}

	if crl.Number == nil {
		res.Warnings = append(res.Warnings, "CRL is missing the X.509 cRLNumber extension")
	}

	return res
}

// ValidateCSR performs sanity and policy checks on a certificate signing request.
func ValidateCSR(csr *x509.CertificateRequest) ValidationResult {
	var res ValidationResult

	if csr.Subject.CommonName == "" {
		res.Issues = append(res.Issues, "Subject missing Common Name (CN)")
	}

	switch csr.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		res.Issues = append(res.Issues, fmt.Sprintf("Insecure signature algorithm used in CSR: %s", csr.SignatureAlgorithm))
	}

	if rsaKey, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keySize := rsaKey.N.BitLen()
		if keySize < 2048 {
			res.Issues = append(res.Issues, fmt.Sprintf("Weak RSA key length (%d bits; minimum required is 2048 bits)", keySize))
		}
	}

	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
		res.Warnings = append(res.Warnings, "CSR contains no Subject Alternative Names (DNS/IP SANs)")
	}

	return res
}
