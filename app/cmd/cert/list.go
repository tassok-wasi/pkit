package cert

import (
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit specifies how many keys to show. if not given then it will show everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N Certificates."`
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	var certs []base.ListCertificatesRow
	var err error

	if lc.Limit == 0 && lc.Offset == 0 {
		err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
			count, err := txQuerier.TotalCertificates(ctx)
			if err != nil {
				return fmt.Errorf("failed to calculate total Certificates: %w", err)
			}
			certs, err = txQuerier.ListCertificates(ctx, base.ListCertificatesParams{Limit: count, Offset: 0})
			if err != nil {
				return fmt.Errorf("failed to list Certificates: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("transaction failed, data rolled back: %w", err)
		}
	} else {
		certs, err = query.ListCertificates(ctx, base.ListCertificatesParams{Limit: int64(lc.Limit), Offset: int64(lc.Offset)})
		if err != nil {
			return fmt.Errorf("failed to list the certificates: %w", err)
		}
	}

	// NOTE: Have to use a library for showing table on terminal
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("|  %s |  %s  |\n", "Serial Number", "Common Name")
	fmt.Println(strings.Repeat("-", 50))
	for _, cert := range certs {
		fmt.Printf("|  %s  |  %s  |\n", cert.SerialNumber, cert.CommonName)
		fmt.Println(strings.Repeat("-", 50))
	}

	return nil
}
