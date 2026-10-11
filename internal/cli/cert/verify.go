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

	"github.com/tassok-wasi/pkit/internal/service"
)

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the certificate to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, svc *service.Service) error {
	fmt.Println("Building and verifying trust chain...")

	chain, err := svc.VerifyCertificateChain(ctx, vc.ID)
	if err != nil {
		return err
	}

	for i := 1; i < len(chain); i++ {
		fmt.Printf(" Verified signature by: %s\n", chain[i].Subject.CommonName)
	}

	rootCert := chain[len(chain)-1]
	fmt.Printf(" Root Anchor Found: %s\n", rootCert.Subject.CommonName)

	fmt.Println("\nCertificate chain successfully verified against a trusted local root anchor!")
	return nil
}
