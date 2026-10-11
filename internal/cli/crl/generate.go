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

	"github.com/tassok-wasi/pkit/internal/service"
)

type GenerateCmd struct {
	IssuerID int64  `name:"iss" help:"Database ID of the issuing certificate to generate the CRL."`
	TTL      string `name:"ttl" default:"168h" required:"" help:"Validity duration/time-to-live until next update for the CRL (e.g., 168h, 7d, 1y)."`
}

func (gc *GenerateCmd) Run(ctx context.Context, svc *service.Service) error {
	_, err := svc.GenerateCRL(ctx, service.GenerateCRLRequest{
		IssuerID: gc.IssuerID,
		TTL:      gc.TTL,
	})
	return err
}
