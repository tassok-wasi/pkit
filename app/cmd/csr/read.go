package csr

import (
	"certman/db/base"
	"context"
	"fmt"
	"strings"
)

type ReadCmd struct {
	ID int64 `arg:"" help:"ID of the CSR to Read."`
}

func (rc *ReadCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from database: %w", err)
	}

	pemData := strings.TrimSpace(dbCsr.CsrPem)
	if pemData == "" {
		return fmt.Errorf("CSR #%d contains no PEM data", rc.ID)
	}

	fmt.Println(pemData)
	return nil
}
