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

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, svc *service.Service) error {
	csrRecord, err := svc.GetCSR(ctx, vc.ID)
	if err != nil {
		return err
	}

	result, err := svc.VerifyCSR(ctx, vc.ID)
	if err != nil {
		return err
	}

	// --- PRINT DIAGNOSTIC REPORT ---
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "PROPERTY\tVALUE\n")
	fmt.Fprintf(w, "--------\t-----\n")
	fmt.Fprintf(w, "CSR ID\t%d\n", csrRecord.ID)
	fmt.Fprintf(w, "Common Name\t%s\n", result.CSR.Subject.CommonName)
	fmt.Fprintf(w, "DNS Names (SANs)\t%v\n", result.CSR.DNSNames)
	fmt.Fprintf(w, "IP Addresses\t%v\n", result.CSR.IPAddresses)
	fmt.Fprintf(w, "Key Type\t%s\n", result.KeyDetail)
	fmt.Fprintf(w, "Status\t%s\n", csrRecord.Status)
	w.Flush()

	fmt.Println()
	if len(result.Issues) > 0 {
		fmt.Println(" Verification Failed with the following issues:")
		for _, issue := range result.Issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("CSR verification failed")
	}

	fmt.Println(" CSR passed all integrity and policy checks!")
	return nil
}
