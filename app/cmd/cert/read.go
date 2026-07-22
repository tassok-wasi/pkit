package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
)

type ReadCmd struct {
	ID int64 `arg:"" help:"Certificate ID"`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	cert, err := utils.ParseCertificate([]byte(dbCert.CertificatePem))
	if err != nil {
		return err
	}

	fmt.Printf("\u2022 Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("\u2022 Common Name: %s\n", dbCert.CommonName)
	fmt.Printf("\u2022 Cert Type: %s\n", dbCert.Type)
	fmt.Printf("\n%s\n", dbCert.CertificatePem)

	return nil
}
