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
	"crypto/x509/pkix"
	"log"

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/service"
)

type GenerateCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the CSR subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the CSR subject."`
	Organization       []string `name:"org" help:"Organization (O) name(s) for the CSR subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the CSR subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the CSR subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the CSR subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the CSR subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the CSR subject."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Cryptographic algorithm and key size to generate for the CSR."`
	DNSNames           []string `name:"dns" help:"DNS Subject Alternative Names (SANs)."`
	EmailAddresses     []string `name:"email" help:"Email Subject Alternative Names (SANs)."`
	IPAddresses        []string `name:"ip" help:"IP address Subject Alternative Names (SANs)."`
	URIs               []string `name:"uri" help:"URI Subject Alternative Names (SANs)."`

	KeyID int64 `name:"kid" short:"k" help:"Database ID of the cryptographic key pair to associate with the CSR."`
}

func (gc *GenerateCmd) Run(ctx context.Context, svc *service.Service) error {
	netIps, err := crypto.ToNetIPs(gc.IPAddresses)
	if err != nil {
		return err
	}
	urls, err := crypto.ToURLs(gc.URIs)
	if err != nil {
		return err
	}

	_, err = svc.GenerateCSR(ctx, service.GenerateCSRRequest{
		Subject: pkix.Name{
			Country:            gc.Country,
			Organization:       gc.Organization,
			OrganizationalUnit: gc.OrganizationalUnit,
			Locality:           gc.Locality,
			Province:           gc.Province,
			StreetAddress:      gc.StreetAddress,
			PostalCode:         gc.PostalCode,
			CommonName:         gc.CommonName,
		},
		SANs: pki.SANs{
			DNSNames:       gc.DNSNames,
			EmailAddresses: gc.EmailAddresses,
			IPAddresses:    netIps,
			URIs:           urls,
		},
		KeyType: gc.KeyType,
		KeyID:   gc.KeyID,
	})
	if err != nil {
		return err
	}

	log.Println("Success: successfully Created Certificate Signing Request.")

	return nil
}
