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
	"log"

	"github.com/tassok-wasi/pkit/internal/service"
)

type RotateCmd struct {
	ID       string `arg:"" help:"short ID of the certificate to rotate."`
	IssuerID string `name:"iss" help:"short ID of the issuing parent certificate (optional for self-signed Root CAs)."`
	KeyID    string `name:"kid" help:"short ID of the new key pair; a new key is generated automatically when omitted."`
	KeyType  string `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Algorithm for the automatically generated key pair (ignored when --kid is provided)."`
}

func (rc *RotateCmd) Run(ctx context.Context, svc *service.Service) error {
	oldCert, err := svc.GetCertificate(ctx, rc.ID)
	if err != nil {
		return err
	}

	if _, err := svc.RotateCertificate(ctx, service.RotateRequest{
		ID:       rc.ID,
		IssuerID: rc.IssuerID,
		KeyID:    rc.KeyID,
		KeyType:  rc.KeyType,
	}); err != nil {
		return err
	}

	log.Printf("Success: Successfully rotated certificate (Old Serial: %s, Type: %s)", oldCert.SerialNumber, oldCert.Type)
	return nil
}
