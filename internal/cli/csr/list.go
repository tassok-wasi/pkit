// Copyright 2026 Tassok Imam Wasi

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csr

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ListCmd struct {
	Limit  int    `name:"limit" short:"l" help:"Maximum number of CSRs to display."`
	Offset int    `name:"offset" short:"o" help:"Number of initial rows to skip for pagination."`
	Status string `name:"status" short:"s" help:"Filter CSRs by status (e.g., PENDING, REJECTED, SIGNED)."`
}

func (lc *ListCmd) Run(ctx context.Context, svc *service.Service) error {
	summaries, err := svc.ListCSRs(ctx, service.ListCSRsRequest{
		Limit:  lc.Limit,
		Offset: lc.Offset,
		Status: lc.Status,
	})
	if err != nil {
		return err
	}

	if len(summaries) == 0 {
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

	for _, csr := range summaries {
		if lc.Status == "SIGNED" {
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\n",
				csr.ID,
				csr.CommonName,
				csr.KeyID,
				csr.Status,
				csr.CertificateID.Int64,
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
