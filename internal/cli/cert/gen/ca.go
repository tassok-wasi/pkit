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

package gen

import (
	"context"
	"crypto/x509/pkix"
	"log"

	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/service"
)

type CACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the certificate subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the certificate subject."`
	Organization       []string `name:"org" help:"Organization (O) name(s) for the certificate subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the certificate subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the certificate subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the certificate subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the certificate subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the certificate subject."`
	TTL                string   `name:"ttl" required:"" default:"86400h" help:"Validity duration/time-to-live for the certificate (e.g., 8760h, 30d, 10y)."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`

	KeyID   string `name:"kid" short:"k" help:"short ID of the key pair; a new key is generated automatically when omitted."`
	KeyType string `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Algorithm for the automatically generated key pair (ignored when --kid is provided)."`
}

func (cc *CACmd) Run(ctx context.Context, svc *service.Service) error {
	_, err := svc.IssueCertificate(ctx, service.IssueRequest{
		Type: pki.TypeRootCA,
		Subject: pkix.Name{
			Country:            cc.Country,
			Organization:       cc.Organization,
			OrganizationalUnit: cc.OrganizationalUnit,
			Locality:           cc.Locality,
			Province:           cc.Province,
			StreetAddress:      cc.StreetAddress,
			PostalCode:         cc.PostalCode,
			CommonName:         cc.CommonName,
		},
		TTL:       cc.TTL,
		KeyID:     cc.KeyID,
		KeyType:   cc.KeyType,
		KeyUsages: cc.KeyUsages,
	})
	if err != nil {
		return err
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
