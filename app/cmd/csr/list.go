package csr

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
	Status string `name:"status" short:"s" help:"Status defines Which are the data to show e.g., PENDING, REJECTED, SIGNED."`
}

// unifiedCSR normalizes the fields from different query row models
type unifiedCSR struct {
	ID            int64
	CommonName    string
	KeyID         int64
	Status        string
	CertificateID sql.NullInt64
}

func (lc *ListCmd) Run(ctx context.Context, query base.Querier) error {
	statusFilter := sql.NullString{
		String: lc.Status,
		Valid:  lc.Status != "",
	}

	var unifiedList []unifiedCSR

	if lc.Limit == 0 && lc.Offset == 0 {
		csrs, err := query.ListAllCSRs(ctx, statusFilter)
		if err != nil {
			return fmt.Errorf("failed to fetch CSRs from DB: %w", err)
		}
		for _, c := range csrs {
			unifiedList = append(unifiedList, unifiedCSR{
				ID:            c.ID,
				CommonName:    c.CommonName,
				KeyID:         c.KeyID,
				Status:        c.Status,
				CertificateID: c.CertificateID,
			})
		}
	} else {
		csrs, err := query.ListCSRs(ctx, base.ListCSRsParams{
			Status: statusFilter,
			Limit:  int64(lc.Limit),
			Offset: int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to fetch CSRs from DB: %w", err)
		}
		for _, c := range csrs {
			unifiedList = append(unifiedList, unifiedCSR{
				ID:            c.ID,
				CommonName:    c.CommonName,
				KeyID:         c.KeyID,
				Status:        c.Status,
				CertificateID: c.CertificateID,
			})
		}
	}

	if len(unifiedList) == 0 {
		fmt.Println("No CSRs found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	if lc.Status == "SIGNED" {
		fmt.Fprintln(w, "ID\tCOMMON NAME\tKEY ID\tSTATUS\tCERTIFICATE SERIAL NUMBER")
		fmt.Fprintln(w, "--\t-----------\t------\t------\t-------------------------")
	} else {
		fmt.Fprintln(w, "ID\tCOMMON NAME\tKEY ID\tSTATUS")
		fmt.Fprintln(w, "--\t-----------\t------\t------")
	}

	for _, csr := range unifiedList {
		if lc.Status == "SIGNED" {
			certID := sql.NullInt64{Int64: 0, Valid: false}
			if csr.CertificateID.Valid {
				certID = csr.CertificateID
			}
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\n",
				csr.ID,
				csr.CommonName,
				csr.KeyID,
				csr.Status,
				certID.Int64,
			)
		} else {
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\n",
				csr.ID,
				csr.CommonName,
				csr.KeyID,
				csr.Status,
			)
		}
	}

	return w.Flush()
}
