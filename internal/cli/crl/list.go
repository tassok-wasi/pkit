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

package crl

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ListCmd struct {
	Limit    int   `name:"limit" short:"l" help:"Maximum number of CRLs to display."`
	Offset   int   `name:"offset" short:"o" help:"Number of initial rows to skip for pagination."`
	IssuerID int64 `name:"iss" required:"" help:"Filter CRLs by the issuing certificate's database ID."`
}

func (lc *ListCmd) Run(ctx context.Context, svc *service.Service) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	fmt.Fprintln(w, "ID\tNAME\tCRL NUMBER\tTHIS UPDATE\tNEXT UPDATE")
	fmt.Fprintln(w, "--\t----\t----------\t-----------\t-----------")

	crls, err := svc.ListCRLs(ctx, service.ListCRLsRequest{
		Limit:    lc.Limit,
		Offset:   lc.Offset,
		IssuerID: lc.IssuerID,
	})
	if err != nil {
		return err
	}

	if len(crls) == 0 {
		fmt.Printf("No CRLs found for issuer serial: %d\n", lc.IssuerID)
		return nil
	}

	for _, crl := range crls {
		thisUpdateStr := crl.ThisUpdate.Format("2006-01-02 15:04:05")
		nextUpdateStr := crl.NextUpdate.Format("2006-01-02 15:04:05")

		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\n",
			crl.ID,
			crl.Name,
			crl.CrlNumber,
			thisUpdateStr,
			nextUpdateStr,
		)
	}
	return w.Flush()
}
