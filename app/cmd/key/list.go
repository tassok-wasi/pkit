package key

import (
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Limit limits the output. if not given then it will show everything."`
	Offset int `name:"offset" short:"o" help:"Skip first N rows."`
}

func (lc *ListCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "KEY NAME\tALGORITHM\tCREATED AT")
	fmt.Fprintln(w, "--------\t---------\t----------")

	if lc.Limit == 0 && lc.Offset == 0 {
		keys, err := query.ListAllKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch keys from database: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

		for _, k := range keys {
			createdAtStr := "N/A"

			if k.CreatedAt.Valid {
				createdAtStr = k.CreatedAt.Time.Format("2006-01-02 15:04:05")
			}

			fmt.Fprintf(w, "%s\t%s\t%s\n",
				k.Name,
				k.Algorithm,
				createdAtStr,
			)
		}
		return w.Flush()
	} else {
		keys, err := query.ListKeys(ctx, base.ListKeysParams{
			Limit:  int64(lc.Limit),
			Offset: int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to fetch keys from database: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

		for _, k := range keys {
			createdAtStr := "N/A"

			if k.CreatedAt.Valid {
				createdAtStr = k.CreatedAt.Time.Format("2006-01-02 15:04:05")
			}

			fmt.Fprintf(w, "%s\t%s\t%s\n",
				k.Name,
				k.Algorithm,
				createdAtStr,
			)
		}
		return w.Flush()
	}
}
