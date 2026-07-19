package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type InspectCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected and one must be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected and one must be selected."`
	Fingerprint  bool   `name:"fingerprint" short:"f" help:"Display SHA-1 and SHA-256 fingerprints."`
	Usage        bool   `name:"key-usages" short:"u" help:"Display X.509 structural key usage flags."`
	Extensions   bool   `name:"extensions" short:"e" help:"Display X.509 structural extension usage flags."`
	JSON         bool   `name:"json" short:"j" help:"Output certificate details in raw JSON format for scripting."`
}

type JSONOutput struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	SignatureAlg string   `json:"signature_algorithm"`
	KeyAlgo      string   `json:"key_algorithm"`
	KeySize      string   `json:"key_size"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	IsCA         bool     `json:"is_ca"`
	KeyUsages    []string `json:"key_usages,omitempty"`
	ExtKeyUsages []string `json:"ext_key_usages,omitempty"`
	SHA1         string   `json:"sha1_fingerprint,omitempty"`
	SHA256       string   `json:"sha256_fingerprint,omitempty"`
}

func (ic *InspectCmd) Run(ctx context.Context, query base.Querier) error {
	cert, err := ic.fetchCertificate(ctx, query)
	if err != nil {
		return err
	}

	keyAlgo, keySize := utils.GetKeyDetails(cert.PublicKey)

	if ic.JSON {
		return ic.outputJSON(cert, keyAlgo, keySize)
	}

	return ic.outputPretty(cert, keyAlgo, keySize)
}

func (icc *InspectCmd) fetchCertificate(ctx context.Context, query base.Querier) (*x509.Certificate, error) {
	var cert *x509.Certificate

	if icc.SerialNumber != "" && icc.CommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, icc.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return nil, err
		}
	} else if icc.SerialNumber == "" && icc.CommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, icc.CommonName)
		if err != nil {
			return nil, fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("exactly one flag (--sn or --cn) must be provided")
	}
	return cert, nil
}

func (ic *InspectCmd) outputJSON(cert *x509.Certificate, keyAlgo, keySize string) error {
	out := JSONOutput{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
		SignatureAlg: cert.SignatureAlgorithm.String(),
		KeyAlgo:      keyAlgo,
		KeySize:      keySize,
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
		DNSNames:     cert.DNSNames,
		IsCA:         cert.IsCA,
	}

	// IP Addresses
	for _, ip := range cert.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}

	// Key Usages
	if ic.Usage {
		out.KeyUsages = utils.MarshalKeyUsage(cert.KeyUsage)
	}

	// Key Extensions
	if ic.Extensions {
		out.ExtKeyUsages = utils.MarshalExtKeyUsages(cert.ExtKeyUsage)
	}

	// Fingerprints
	if ic.Fingerprint {
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		out.SHA1 = utils.FormatFingerprint(sum1[:])
		out.SHA256 = utils.FormatFingerprint(sum256[:])
	}

	jsonBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}

func (ic *InspectCmd) outputPretty(cert *x509.Certificate, keyAlgo, keySize string) error {
	fmt.Println("Certificate Inspection Report")
	fmt.Println(strings.Repeat("─", 50))

	// Print Full Subject Properties
	fmt.Println("  [ Subject Identity ]")
	fmt.Printf("    \u2022 Full DN: %s\n", cert.Subject.String())
	if cert.Subject.CommonName != "" {
		fmt.Printf("    \u2022 Common Name (CN): %s\n", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("    \u2022 Organization (O): %s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.Country) > 0 {
		fmt.Printf("    \u2022 Country (C)     : %s\n", strings.Join(cert.Subject.Country, ", "))
	}

	fmt.Println(strings.Repeat("─", 50))

	// Print Full Issuer Properties
	fmt.Println("  [ Issuer / Signer Identity ]")
	fmt.Printf("    \u2022 Full DN: %s\n", cert.Issuer.String())

	fmt.Println(strings.Repeat("─", 50))

	// Print Technical & Crypto Metadata
	fmt.Println("  [ Cryptographic Metadata ]")
	fmt.Printf("    \u2022 Serial Number: %x\n", cert.SerialNumber)
	fmt.Printf("    \u2022 Signature Alg: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("    \u2022 Public Key   : %s (%s)\n", keyAlgo, keySize)

	fmt.Println(strings.Repeat("─", 50))

	// Print Lifecycle Timeline
	fmt.Println("  [ Validity Lifecycle ]")
	fmt.Printf("    \u2022 Active From  : %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    \u2022 Expires On   : %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Println(strings.Repeat("─", 50))

	// Print Alternative Target Entities if active
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Println("  [ Subject Alternative Names (SAN) ]")
		if len(cert.DNSNames) > 0 {
			fmt.Printf("    \u2022 DNS Domains  : %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for i, ip := range cert.IPAddresses {
				ips[i] = ip.String()
			}
			fmt.Printf("    \u2022 IP Addresses : %v\n", strings.Join(ips, ", "))
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --fingerprint flag ---
	if ic.Fingerprint {
		fmt.Println("  [ Certificate Fingerprints ]")
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		fmt.Printf("    \u2022 SHA-1  : %s\n", utils.FormatFingerprint(sum1[:]))
		fmt.Printf("    \u2022 SHA-256: %s\n", utils.FormatFingerprint(sum256[:]))
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --usage flag ---
	if ic.Usage {
		fmt.Println("  [ Key Usage ]")

		usages := utils.MarshalKeyUsage(cert.KeyUsage)
		if len(usages) > 0 {
			fmt.Printf("    \u2022 Intended Key Usages   : %s\n", strings.Join(usages, ", "))
		} else {
			fmt.Println("    \u2022 Intended Key Usages   : None Specified")
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --extensions flag ---
	if ic.Extensions {
		fmt.Println("  [ Extended Key Usage ]")

		usages := utils.MarshalExtKeyUsages(cert.ExtKeyUsage)
		if len(usages) > 0 {
			fmt.Printf("    \u2022 Extended Key Usages   : %s\n", strings.Join(usages, ", "))
		} else {
			fmt.Println("    \u2022 Extended Key Usages   : None Specified")
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- CA FLAG (only show if we haven't already) ---
	if !ic.Usage && !ic.Extensions {
		fmt.Println("  [ Basic Constraints ]")
		fmt.Printf("    \u2022 Is CA Certificate     : %t\n", cert.IsCA)
		fmt.Println(strings.Repeat("─", 50))
	}

	return nil
}
