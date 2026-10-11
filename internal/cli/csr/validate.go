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

	"github.com/tassok-wasi/pkit/internal/service"
)

type ValidateCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to validate."`
}

func (vc *ValidateCmd) Run(ctx context.Context, svc *service.Service) error {
	csr, err := svc.GetParsedCSR(ctx, vc.ID)
	if err != nil {
		return err
	}

	result, err := svc.ValidateCSR(ctx, vc.ID)
	if err != nil {
		return err
	}

	fmt.Printf("Validating CSR ID %d [%s]...\n\n", vc.ID, csr.Subject.CommonName)

	// Output Warnings
	if len(result.Warnings) > 0 {
		fmt.Println(" Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	// Output Issues & Exit Status
	if len(result.Issues) > 0 {
		fmt.Println("\n Validation Failed:")
		for _, issue := range result.Issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("csr validation failed with %d error(s)", len(result.Issues))
	}

	fmt.Println(" All CSR sanity checks passed!")
	return nil
}
