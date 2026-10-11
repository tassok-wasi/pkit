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

package cert

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ListCmd struct {
	Limit  int    `name:"limit" short:"l" help:"Maximum number of certificates to display."`
	Offset int    `name:"offset" short:"o" help:"Number of initial rows to skip for pagination."`
	Status string `name:"status" short:"s" help:"Filter certificates by status (e.g., ACTIVE, REVOKED, EXPIRED)."`
	Type   string `name:"type" short:"t" help:"Filter certificates by type (e.g., CA, INTERMEDIATE, LEAF)."`
}

func (lc *ListCmd) Run(ctx context.Context, svc *service.Service) error {
	certs, err := svc.ListCertificates(ctx, service.ListCertificatesRequest{
		Limit:  lc.Limit,
		Offset: lc.Offset,
		Status: lc.Status,
		Type:   lc.Type,
	})
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found matching criteria.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "ID\tSERIAL NUMBER\tCOMMON NAME\tTYPE\tSTATUS\tCREATED AT")
	fmt.Fprintln(w, "--\t-----\t-----------\t----\t------\t---------")

	for _, cert := range certs {
		createdAt := "N/A"
		if !cert.CreatedAt.IsZero() {
			createdAt = cert.CreatedAt.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			cert.ID,
			cert.SerialNumber,
			cert.CommonName,
			cert.Type,
			cert.Status,
			createdAt,
		)
	}

	return w.Flush()
}
