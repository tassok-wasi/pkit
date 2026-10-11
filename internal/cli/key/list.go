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

package key

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ListCmd struct {
	Limit  int `name:"limit" short:"l" help:"Maximum number of key pairs to display."`
	Offset int `name:"offset" short:"o" help:"Number of initial rows to skip for pagination."`
}

func (lc *ListCmd) Run(ctx context.Context, svc *service.Service) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "ID\tKEY NAME\tALGORITHM\tCREATED AT")
	fmt.Fprintln(w, "--\t--------\t---------\t----------")

	keys, err := svc.ListKeys(ctx, service.ListKeysRequest{
		Limit:  lc.Limit,
		Offset: lc.Offset,
	})
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No keys found.")
		return nil
	}

	for _, k := range keys {
		createdAtStr := "N/A"

		if !k.CreatedAt.IsZero() {
			createdAtStr = k.CreatedAt.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			k.ID,
			k.Name,
			k.Algorithm,
			createdAtStr,
		)
	}
	return w.Flush()
}
