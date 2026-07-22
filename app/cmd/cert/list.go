package cert

import (
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListCmd struct {
	Limit  int    `name:"limit" short:"l" help:"Limit limits the output. if not given then it will show everything."`
	Offset int    `name:"offset" short:"o" help:"Skip first N rows."`
	Status string `name:"status" short:"s" help:"Shows the data those matches with the status. e.g., ACTIVE, REVOKED, EXPIRED."`
	Type   string `name:"type" short:"t" help:"Certificate Type e.g., CA, INTERMEDIATE, LEAF"`
}

// unifiedCert normalizes output from paginated and non-paginated queries
type unifiedCert struct {
	ID           int64
	SerialNumber string
	CommonName   string
	Type         string
	Status       string
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	statusFilter := toNullString(lc.Status)
	typeFilter := toNullString(lc.Type)

	var list []unifiedCert

	if lc.Limit == 0 && lc.Offset == 0 {
		certs, err := query.ListAllCertificates(ctx, base.ListAllCertificatesParams{
			Status: statusFilter,
			Type:   typeFilter,
		})
		if err != nil {
			return fmt.Errorf("failed to fetch certificates from database: %w", err)
		}
		for _, c := range certs {
			list = append(list, unifiedCert{
				ID:           c.ID,
				SerialNumber: c.SerialNumber,
				CommonName:   c.CommonName,
				Type:         c.Type,
				Status:       c.Status,
			})
		}
	} else {
		certs, err := query.ListCertificates(ctx, base.ListCertificatesParams{
			Status: statusFilter,
			Type:   typeFilter,
			Limit:  int64(lc.Limit),
			Offset: int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to fetch certificates from database: %w", err)
		}
		for _, c := range certs {
			list = append(list, unifiedCert{
				ID:           c.ID,
				SerialNumber: c.SerialNumber,
				CommonName:   c.CommonName,
				Type:         c.Type,
				Status:       c.Status,
			})
		}
	}

	if len(list) == 0 {
		fmt.Println("No certificates found matching criteria.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "ID\tSERIAL NUMBER\tCOMMON NAME\tTYPE\tSTATUS")
	fmt.Fprintln(w, "--\t-----\t-----------\t----\t------")

	for _, cert := range list {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			cert.ID,
			cert.SerialNumber,
			cert.CommonName,
			cert.Type,
			cert.Status,
		)
	}

	return w.Flush()
}

// Helper to convert plain string inputs to sql.NullString for dynamic filtering
func toNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}
