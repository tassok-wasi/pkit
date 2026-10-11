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

type RevokeCmd struct {
	ID     int64  `arg:"" help:"Database ID of the certificate to revoke."`
	Reason string `name:"reason" short:"r" required:"" enum:"unspecified,key-compromise,ca-compromise,affiliation-changed,superseded,cessation-of-operation,certificate-hold,remove-from-crl,privilege-withdrawn,a-a-compromise" help:"Revocation reason code for the certificate."`
}

func (rc *RevokeCmd) Run(ctx context.Context, svc *service.Service) error {
	if err := svc.RevokeCertificate(ctx, rc.ID, rc.Reason); err != nil {
		return err
	}

	fmt.Println("Successfully Revoked Certificate.")

	return nil
}
