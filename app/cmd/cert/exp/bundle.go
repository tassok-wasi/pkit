package exp

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type BundleCmd struct {
	ID          int64  `arg:"" help:"ID of the leaf certificate to build fullchain/bundle for."`
	Path        string `name:"path" short:"p" help:"Output path or directory for the merged PEM file."`
	IncludeRoot bool   `name:"include-root" help:"Include the root certificate at the end of the chain." default:"false"`
}

func (bc *BundleCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, bc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch target certificate ID %d: %w", bc.ID, err)
	}

	targetCert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return fmt.Errorf("failed to parse target certificate: %w", err)
	}

	fmt.Printf("Merging certificate chain for '%s'...\n", targetCert.Subject.CommonName)

	// 2. Build PEM chain (starting with target leaf cert)
	var pemBlocks []string
	pemBlocks = append(pemBlocks, strings.TrimSpace(dbCert.CertificatePem))

	workingCert := targetCert
	const maxChainDepth = 10

	for depth := range maxChainDepth {
		if workingCert.Subject.String() == workingCert.Issuer.String() {
			if bc.IncludeRoot {
				fmt.Printf("Added Root CA: %s\n", workingCert.Subject.CommonName)
			} else {
				fmt.Printf("Omitting Root CA anchor: %s (use --include-root to include)\n", workingCert.Subject.CommonName)
				if depth == 0 {
					pemBlocks = pemBlocks[:1]
				}
			}
			break
		}

		if len(workingCert.AuthorityKeyId) == 0 {
			fmt.Printf("Chain ended early: '%s' lacks AKID\n", workingCert.Subject.CommonName)
			break
		}

		akidHex := hex.EncodeToString(workingCert.AuthorityKeyId)
		parentDBCert, err := query.GetCertificateBySKID(ctx, akidHex)
		if err != nil {
			return fmt.Errorf("failed to complete bundle: parent cert with SKID [%s] not found in DB: %w", akidHex, err)
		}

		parentCert, err := utils.ParseCertificate([]byte(parentDBCert.CertificatePem))
		if err != nil {
			return fmt.Errorf("failed to parse parent certificate: %w", err)
		}

		// If next cert is root and user did not request root inclusion, skip adding its PEM block
		isRoot := parentCert.Subject.String() == parentCert.Issuer.String()
		if !isRoot || bc.IncludeRoot {
			pemBlocks = append(pemBlocks, strings.TrimSpace(parentDBCert.CertificatePem))
			fmt.Printf("Added Intermediate/Issuer: %s\n", parentCert.Subject.CommonName)
		}

		workingCert = parentCert
	}

	mergedPEM := strings.Join(pemBlocks, "\n\n") + "\n"

	defaultFilename := utils.SanitizeFilename(targetCert.Subject.CommonName, "merged_chain") + "_fullchain.pem"
	outPath, err := utils.ResolveDestinationPath(bc.Path, defaultFilename, ".pem")
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(outPath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(outPath, []byte(mergedPEM), 0o644); err != nil {
		return fmt.Errorf("failed to write merged certificate chain to %s: %w", outPath, err)
	}

	fmt.Printf("\nMerged fullchain written to: %s\n", outPath)
	return nil
}
