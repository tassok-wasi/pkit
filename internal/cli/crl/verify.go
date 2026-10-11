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
	"time"

	"github.com/tassok-wasi/pkit/internal/service"
)

type VerifyCmd struct {
	ID int64 `arg:"" help:"Database ID of the CRL to verify."`
}

func (vc *VerifyCmd) Run(ctx context.Context, svc *service.Service) error {
	parsedCRL, err := svc.VerifyCRL(ctx, vc.ID)
	if err != nil {
		return err
	}

	fmt.Println(" Cryptographic Signature: Valid (Signed securely by the Issuer)")

	now := time.Now()
	if now.After(parsedCRL.NextUpdate) {
		fmt.Printf("  Validity Warning: This CRL is EXPIRED!\n")
		fmt.Printf("   Next Update was scheduled for: %s\n", parsedCRL.NextUpdate.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("Validity Status: Current (Expires on: %s)\n", parsedCRL.NextUpdate.Format("2006-01-02 15:04:05"))
	}

	return nil
}
