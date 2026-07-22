package csr

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

type ExportCmd struct {
	ID     int64  `arg:"" help:"ID of the CSR to Export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path."`
	Format string `name:"format" short:"f" default:"pem" help:"Specific format to export (e.g., pem, der)"`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, ec.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(ec.Format))
	if format == "" {
		format = "pem"
	}

	var data []byte
	var ext string

	switch format {
	case "pem":
		ext = ".pem"
		data = []byte(dbCsr.CsrPem)

	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCsr.CsrPem))
		if block == nil {
			return errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes

	default:
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", ec.Format)
	}

	csrFilePath, err := utils.ResolveDestinationPath(ec.Path, dbCsr.CommonName, ext)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	targetDir := filepath.Dir(csrFilePath)
	if targetDir != "." && targetDir != "" {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}
	}

	if err := os.WriteFile(csrFilePath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", csrFilePath, err)
	}

	fmt.Printf("Successfully exported CSR to: %s\n", csrFilePath)
	return nil
}
