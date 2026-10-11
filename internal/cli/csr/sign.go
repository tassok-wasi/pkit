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
	"log"

	"github.com/tassok-wasi/pkit/internal/service"
)

type SignCmd struct {
	ID           int64    `arg:"" help:"Database ID of the CSR to sign."`
	Type         string   `name:"type" required:"" help:"Type of certificate to issue (e.g., CA, INTERMEDIATE, LEAF)."`
	TTL          string   `name:"ttl" required:"" default:"8760h" help:"Validity duration/time-to-live for the issued certificate (e.g., 8760h, 30d, 1y)."`
	KeyUsages    []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`
	ExtKeyUsages []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Extended key usage (EKU) extensions to enable (can be specified multiple times or comma-separated)."`
	PathLen      int      `name:"path-len" help:"Maximum allowed path length for downstream CA certificates (omit for non-CA certificates)."`

	IssuerID int64 `name:"iss" help:"Database ID of the issuing parent certificate."`
}

func (sc *SignCmd) Run(ctx context.Context, svc *service.Service) error {
	_, err := svc.SignCSR(ctx, service.SignCSRRequest{
		ID:           sc.ID,
		Type:         sc.Type,
		TTL:          sc.TTL,
		KeyUsages:    sc.KeyUsages,
		ExtKeyUsages: sc.ExtKeyUsages,
		PathLen:      sc.PathLen,
		IssuerID:     sc.IssuerID,
	})
	if err != nil {
		return err
	}

	log.Println("Succes: successfully created Certificate.")

	return nil
}
