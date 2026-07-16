package cmd

import (
	"certman/app/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"strings"
)

type InspectCmd struct {
	Cert InspectCertCmd `cmd:"" help:"Prints raw Certificate in stdout."`
	Key  InspectKeyCmd  `cmd:"" help:"Prints raw Key in stdout."`
}

type InspectCertCmd struct {
	Path string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert) format."`
}

func (icc *InspectCertCmd) Run() error {
	cert, err := utils.ReadCert(icc.Path)
	if err != nil {
		return err
	}

	keyAlgo, keySize := getKeyDetails(cert.PublicKey)

	fmt.Println("Certificate Inspection Report")
	fmt.Println(strings.Repeat("─", 50))

	// Print Full Subject Properties
	fmt.Println("  [ Subject Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Subject))
	if cert.Subject.CommonName != "" {
		fmt.Printf("    • Common Name (CN): %s\n", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("    • Organization (O): %s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.Country) > 0 {
		fmt.Printf("    • Country (C)     : %s\n", strings.Join(cert.Subject.Country, ", "))
	}

	fmt.Println(strings.Repeat("─", 50))

	// Print Full Issuer Properties
	fmt.Println("  [ Issuer / Signer Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Issuer))

	fmt.Println(strings.Repeat("─", 50))

	// Print Technical & Crypto Metadata
	fmt.Println("  [ Cryptographic Metadata ]")
	fmt.Printf("    • Serial Number: %x\n", cert.SerialNumber)
	fmt.Printf("    • Signature Alg: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("    • Public Key   : %s (%s)\n", keyAlgo, keySize)

	fmt.Println(strings.Repeat("─", 50))

	// Print Lifecycle Timeline
	fmt.Println("  [ Validity Lifecycle ]")
	fmt.Printf("    • Active From  : %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    • Expires On   : %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Println(strings.Repeat("─", 50))

	// Print Alternative Target Entities if active
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Println("  [ Subject Alternative Names (SAN) ]")
		if len(cert.DNSNames) > 0 {
			fmt.Printf("    • DNS Domains  : %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			fmt.Printf("    • IP Addresses : %v\n", cert.IPAddresses)
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	return nil
}

type InspectKeyCmd struct {
	Path string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.key,.pem) format."`
}

func (ikc *InspectKeyCmd) Run() error {
	key, blockType, err := utils.ReturnKeyWithBlockType(ikc.Path)
	if err != nil {
		return err
	}

	fmt.Printf("Key Inspection Report\n")
	fmt.Println(strings.Repeat("─", 55))
	fmt.Printf("  • PEM Block Header Type: %s\n", blockType)

	switch k := key.(type) {

	// ==================== RSA KEY TYPES ====================
	case *rsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))
		fmt.Printf("  • Prime Factor (P) Size : %d bits\n", len(k.Primes[0].Bytes())*8)
		fmt.Printf("  • Prime Factor (Q) Size : %d bits\n", len(k.Primes[1].Bytes())*8)

	case *rsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))

	// ==================== ECDSA KEY TYPES ====================
	case *ecdsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		fmt.Printf("  • Order Limit (N)       : %s...\n", truncateHex(k.Params().N.Bytes()))
		fmt.Printf("  • Private Scalar D      : [Protected / Hidden in Memory]\n")
		// Safely extract the matching Public Key coordinates using modern standard conventions
		pubBytes := elliptic.Marshal(k.Curve, k.X, k.Y)
		fmt.Printf("  • Linked Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

	case *ecdsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		// Safely extract point layout to avoid using deprecated direct .X or .Y coordinate properties
		pubBytes := elliptic.Marshal(k.Curve, k.X, k.Y)
		fmt.Printf("  • Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

	// ==================== ED25519 KEY TYPES ====================
	case ed25519.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Key Seed Payload      : %s...\n", truncateHex(k.Seed()))

		pub, _ := k.Public().(ed25519.PublicKey)
		fmt.Printf("  • Extracted Public Key  : %s\n", hex.EncodeToString(pub))

	case ed25519.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Complete Public Point : %s\n", hex.EncodeToString(k))

	default:
		fmt.Printf("  • Structural Type Unknown: %T\n", k)
	}

	fmt.Println(strings.Repeat("─", 55))
	return nil
}

// FormatDN builds a clean, readable string from a pkix.Name struct (e.g., "CN=MyRoot, O=MyOrg, C=US")
func formatDN(name pkix.Name) string {
	var parts []string

	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}
	if len(name.Organization) > 0 {
		parts = append(parts, fmt.Sprintf("O=%s", strings.Join(name.Organization, ", ")))
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, fmt.Sprintf("OU=%s", strings.Join(name.OrganizationalUnit, ", ")))
	}
	if len(name.Country) > 0 {
		parts = append(parts, fmt.Sprintf("C=%s", strings.Join(name.Country, ", ")))
	}
	if len(name.Province) > 0 {
		parts = append(parts, fmt.Sprintf("ST=%s", strings.Join(name.Province, ", ")))
	}
	if len(name.Locality) > 0 {
		parts = append(parts, fmt.Sprintf("L=%s", strings.Join(name.Locality, ", ")))
	}

	if len(parts) == 0 {
		return "Empty Distinguished Name"
	}
	return strings.Join(parts, ", ")
}

func getKeyDetails(key any) (algoType string, sizeInfo string) {
	switch k := key.(type) {
	// --- Private Key Types ---
	case *rsa.PrivateKey:
		algoType = "RSA Private Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PrivateKey:
		algoType = "ECDSA Private Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PrivateKey:
		algoType = "Ed25519 Private Key"
		sizeInfo = "256-bit seed"

	// --- Public Key Types ---
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

func truncateHex(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	fullHex := hex.EncodeToString(b)
	if len(fullHex) > 32 {
		return fullHex[:32]
	}
	return fullHex
}
