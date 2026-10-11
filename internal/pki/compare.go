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
	"crypto/x509/pkix"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tassok-wasi/pkit/internal/crypto"
)

// FieldDiff represents a single differing field between two PKI objects.
type FieldDiff struct {
	Field string
	Val1  string
	Val2  string
}

// ComparePkixName exhaustively compares two pkix.Name structs, reporting each
// differing attribute through addDiff.
func ComparePkixName(prefix string, n1, n2 pkix.Name, addDiff func(string, string, string)) {
	if n1.CommonName != n2.CommonName {
		addDiff(prefix+" CN", n1.CommonName, n2.CommonName)
	}
	if !reflect.DeepEqual(n1.Organization, n2.Organization) {
		addDiff(prefix+" Org (O)", strings.Join(n1.Organization, ", "), strings.Join(n2.Organization, ", "))
	}
	if !reflect.DeepEqual(n1.OrganizationalUnit, n2.OrganizationalUnit) {
		addDiff(prefix+" OU", strings.Join(n1.OrganizationalUnit, ", "), strings.Join(n2.OrganizationalUnit, ", "))
	}
	if !reflect.DeepEqual(n1.Country, n2.Country) {
		addDiff(prefix+" Country (C)", strings.Join(n1.Country, ", "), strings.Join(n2.Country, ", "))
	}
	if !reflect.DeepEqual(n1.Province, n2.Province) {
		addDiff(prefix+" State/Province (ST)", strings.Join(n1.Province, ", "), strings.Join(n2.Province, ", "))
	}
	if !reflect.DeepEqual(n1.Locality, n2.Locality) {
		addDiff(prefix+" Locality (L)", strings.Join(n1.Locality, ", "), strings.Join(n2.Locality, ", "))
	}
	if !reflect.DeepEqual(n1.StreetAddress, n2.StreetAddress) {
		addDiff(prefix+" Street Address", strings.Join(n1.StreetAddress, ", "), strings.Join(n2.StreetAddress, ", "))
	}
	if !reflect.DeepEqual(n1.PostalCode, n2.PostalCode) {
		addDiff(prefix+" Postal Code", strings.Join(n1.PostalCode, ", "), strings.Join(n2.PostalCode, ", "))
	}
}

// CompareCertificates reports the structural differences between two X.509 certificates.
func CompareCertificates(c1, c2 *x509.Certificate) []FieldDiff {
	var diffs []FieldDiff

	addDiff := func(field, val1, val2 string) {
		if val1 == "" {
			val1 = "<none>"
		}
		if val2 == "" {
			val2 = "<none>"
		}
		diffs = append(diffs, FieldDiff{Field: field, Val1: val1, Val2: val2})
	}

	if c1.SerialNumber.Cmp(c2.SerialNumber) != 0 {
		addDiff("Serial Number", c1.SerialNumber.String(), c2.SerialNumber.String())
	}

	ComparePkixName("Subject", c1.Subject, c2.Subject, addDiff)
	ComparePkixName("Issuer", c1.Issuer, c2.Issuer, addDiff)

	if !c1.NotBefore.Equal(c2.NotBefore) {
		addDiff("Valid From", c1.NotBefore.Format(time.RFC3339), c2.NotBefore.Format(time.RFC3339))
	}
	if !c1.NotAfter.Equal(c2.NotAfter) {
		addDiff("Valid Until", c1.NotAfter.Format(time.RFC3339), c2.NotAfter.Format(time.RFC3339))
	}

	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}
	if c1.PublicKeyAlgorithm != c2.PublicKeyAlgorithm {
		addDiff("Public Key Alg", c1.PublicKeyAlgorithm.String(), c2.PublicKeyAlgorithm.String())
	}

	if !reflect.DeepEqual(c1.DNSNames, c2.DNSNames) {
		addDiff("SAN: DNS Names", strings.Join(c1.DNSNames, ", "), strings.Join(c2.DNSNames, ", "))
	}
	if !reflect.DeepEqual(c1.EmailAddresses, c2.EmailAddresses) {
		addDiff("SAN: Email Addrs", strings.Join(c1.EmailAddresses, ", "), strings.Join(c2.EmailAddresses, ", "))
	}
	if !crypto.IpSlicesEqual(c1.IPAddresses, c2.IPAddresses) {
		addDiff("SAN: IP Addresses", crypto.FormatIPs(c1.IPAddresses), crypto.FormatIPs(c2.IPAddresses))
	}
	if !crypto.UriSlicesEqual(c1.URIs, c2.URIs) {
		addDiff("SAN: URIs", crypto.FormatURIs(c1.URIs), crypto.FormatURIs(c2.URIs))
	}

	if c1.KeyUsage != c2.KeyUsage {
		addDiff("Key Usage", fmt.Sprintf("0x%x", c1.KeyUsage), fmt.Sprintf("0x%x", c2.KeyUsage))
	}
	if !reflect.DeepEqual(c1.ExtKeyUsage, c2.ExtKeyUsage) {
		addDiff("Ext Key Usage", fmt.Sprint(c1.ExtKeyUsage), fmt.Sprint(c2.ExtKeyUsage))
	}

	if c1.IsCA != c2.IsCA {
		addDiff("Is CA", fmt.Sprintf("%t", c1.IsCA), fmt.Sprintf("%t", c2.IsCA))
	}
	if c1.MaxPathLen != c2.MaxPathLen || c1.MaxPathLenZero != c2.MaxPathLenZero {
		addDiff("Max Path Length", fmt.Sprint(c1.MaxPathLen), fmt.Sprint(c2.MaxPathLen))
	}

	return diffs
}

// CompareCRLs reports the structural differences between two X.509 revocation lists.
func CompareCRLs(c1, c2 *x509.RevocationList) []FieldDiff {
	var diffs []FieldDiff

	addDiff := func(field, val1, val2 string) {
		if val1 == "" {
			val1 = "<none>"
		}
		if val2 == "" {
			val2 = "<none>"
		}
		diffs = append(diffs, FieldDiff{Field: field, Val1: val1, Val2: val2})
	}

	c1Num := "<none>"
	if c1.Number != nil {
		c1Num = c1.Number.String()
	}
	c2Num := "<none>"
	if c2.Number != nil {
		c2Num = c2.Number.String()
	}
	if c1Num != c2Num {
		addDiff("CRL Number", c1Num, c2Num)
	}

	ComparePkixName("Issuer", c1.Issuer, c2.Issuer, addDiff)

	if !c1.ThisUpdate.Equal(c2.ThisUpdate) {
		addDiff("This Update", c1.ThisUpdate.Format(time.RFC3339), c2.ThisUpdate.Format(time.RFC3339))
	}
	if !c1.NextUpdate.Equal(c2.NextUpdate) {
		addDiff("Next Update", c1.NextUpdate.Format(time.RFC3339), c2.NextUpdate.Format(time.RFC3339))
	}

	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}

	if len(c1.RevokedCertificateEntries) != len(c2.RevokedCertificateEntries) {
		addDiff("Revoked Count",
			fmt.Sprintf("%d entry(ies)", len(c1.RevokedCertificateEntries)),
			fmt.Sprintf("%d entry(ies)", len(c2.RevokedCertificateEntries)))
	}

	diffRevokedEntries(c1.RevokedCertificateEntries, c2.RevokedCertificateEntries, addDiff)

	return diffs
}

func diffRevokedEntries(entries1, entries2 []x509.RevocationListEntry, addDiff func(string, string, string)) {
	m1 := make(map[string]x509.RevocationListEntry)
	for _, entry := range entries1 {
		m1[fmt.Sprintf("%X", entry.SerialNumber)] = entry
	}

	m2 := make(map[string]x509.RevocationListEntry)
	for _, entry := range entries2 {
		m2[fmt.Sprintf("%X", entry.SerialNumber)] = entry
	}

	for serial := range m2 {
		if _, exists := m1[serial]; !exists {
			addDiff(fmt.Sprintf("Revoked Serial [%s]", serial), "<not present>", "Present")
		}
	}

	for serial := range m1 {
		if _, exists := m2[serial]; !exists {
			addDiff(fmt.Sprintf("Revoked Serial [%s]", serial), "Present", "<not present>")
		}
	}
}

// CompareCSRs reports the structural differences between two certificate signing requests.
func CompareCSRs(c1, c2 *x509.CertificateRequest) []FieldDiff {
	var diffs []FieldDiff

	addDiff := func(field, val1, val2 string) {
		if val1 == "" {
			val1 = "<none>"
		}
		if val2 == "" {
			val2 = "<none>"
		}
		diffs = append(diffs, FieldDiff{Field: field, Val1: val1, Val2: val2})
	}

	ComparePkixName("Subject", c1.Subject, c2.Subject, addDiff)

	if c1.SignatureAlgorithm != c2.SignatureAlgorithm {
		addDiff("Sig Algorithm", c1.SignatureAlgorithm.String(), c2.SignatureAlgorithm.String())
	}

	k1 := FormatPublicKey(c1.PublicKey)
	k2 := FormatPublicKey(c2.PublicKey)
	if k1 != k2 {
		addDiff("Public Key", k1, k2)
	}

	if !reflect.DeepEqual(c1.DNSNames, c2.DNSNames) {
		addDiff("SAN: DNS Names", strings.Join(c1.DNSNames, ", "), strings.Join(c2.DNSNames, ", "))
	}
	if !reflect.DeepEqual(c1.EmailAddresses, c2.EmailAddresses) {
		addDiff("SAN: Email Addrs", strings.Join(c1.EmailAddresses, ", "), strings.Join(c2.EmailAddresses, ", "))
	}
	if !crypto.IpSlicesEqual(c1.IPAddresses, c2.IPAddresses) {
		addDiff("SAN: IP Addresses", crypto.FormatIPs(c1.IPAddresses), crypto.FormatIPs(c2.IPAddresses))
	}
	if !crypto.UriSlicesEqual(c1.URIs, c2.URIs) {
		addDiff("SAN: URIs", crypto.FormatURIs(c1.URIs), crypto.FormatURIs(c2.URIs))
	}

	return diffs
}

// FormatPublicKey renders a human-readable description of a public key.
func FormatPublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d bits)", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", pub)
	}
}
