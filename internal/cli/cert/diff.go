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

type DiffCmd struct {
	ID1 int64 `arg:"" help:"Database ID of the first certificate to compare."`
	ID2 int64 `arg:"" help:"Database ID of the second certificate to compare."`
}

func (dc *DiffCmd) Run(ctx context.Context, svc *service.Service) error {
	result, err := svc.DiffCertificates(ctx, dc.ID1, dc.ID2)
	if err != nil {
		return err
	}

	fmt.Printf("Comparing Certificate #%d [%s] vs Certificate #%d [%s]\n\n",
		dc.ID1, result.Name1,
		dc.ID2, result.Name2)

	if len(result.Diffs) == 0 {
		fmt.Println("Certificates are functionally identical across all X.509 parameters.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintf(w, "FIELD\tCERT #%d\tCERT #%d\n", dc.ID1, dc.ID2)
	fmt.Fprintln(w, "-----\t--------\t--------")

	for _, diff := range result.Diffs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", diff.Field, diff.Val1, diff.Val2)
	}

	return w.Flush()
}
