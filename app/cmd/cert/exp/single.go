package exp

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SingleCmd struct {
	ID     int64  `arg:"" help:"ID of the Certificate to Export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path."`
	Format string `name:"format" short:"f" default:"pem" help:"Specific format to export (e.g., pem, der)"`
}

func (sc *SingleCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, sc.ID)
	if err != nil {
		return fmt.Errorf("failed to get Certificate from db: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(sc.Format))
	if format == "" {
		format = "pem"
	}

	var data []byte
	var ext string

	switch format {
	case "pem":
		ext = ".pem"
		data = []byte(dbCert.CertificatePem)

	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCert.CertificatePem))
		if block == nil {
			return errors.New("failed to decode PEM formatted Certificate into DER")
		}
		data = block.Bytes

	default:
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", sc.Format)
	}

	certFilePath, err := utils.ResolveDestinationPath(sc.Path, dbCert.CommonName, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(certFilePath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(certFilePath, data, 0o644); err != nil {
		return fmt.Errorf("could not write to file %s: %w", certFilePath, err)
	}

	fmt.Printf("Successfully exported Certificate to: %s\n", certFilePath)
	return nil
}
