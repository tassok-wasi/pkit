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

	"github.com/tassok-wasi/pkit/internal/crypto"
	"github.com/tassok-wasi/pkit/internal/pki"
	"github.com/tassok-wasi/pkit/internal/service"
)

type LeafCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name (CN) of the certificate subject."`
	Country            []string `name:"c" help:"Country (C) code(s) for the certificate subject."`
	Organization       []string `name:"org" help:"Organization (O) name(s) for the certificate subject."`
	OrganizationalUnit []string `name:"ou" help:"Organizational Unit (OU) name(s) for the certificate subject."`
	Locality           []string `name:"locality" help:"Locality or city (L) name(s) for the certificate subject."`
	Province           []string `name:"st" help:"State or province (ST) name(s) for the certificate subject."`
	StreetAddress      []string `name:"street" help:"Street address(es) for the certificate subject."`
	PostalCode         []string `name:"postal-code" help:"Postal code(s) for the certificate subject."`
	TTL                string   `name:"ttl" required:"" default:"8760h" help:"Validity duration/time-to-live for the certificate (e.g., 8760h, 30d, 10y)."`
	DNSNames           []string `name:"dns" help:"DNS Subject Alternative Names (SANs)."`
	EmailAddresses     []string `name:"email" help:"Email Subject Alternative Names (SANs)."`
	IPAddresses        []string `name:"ip" help:"IP address Subject Alternative Names (SANs)."`
	URIs               []string `name:"uri" help:"URI Subject Alternative Names (SANs)."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Key usage extensions to enable (can be specified multiple times or comma-separated)."`
	ExtKeyUsages       []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Extended key usage (EKU) extensions to enable (can be specified multiple times or comma-separated)."`

	IssuerID int64 `name:"iss" help:"Database ID of the issuing parent certificate."`
	KeyID    int64 `name:"kid" short:"k" help:"Database ID of the cryptographic key pair used to sign the certificate."`
}

func (lc *LeafCmd) Run(ctx context.Context, svc *service.Service) error {
	netIps, err := crypto.ToNetIPs(lc.IPAddresses)
	if err != nil {
		return err
	}
	urls, err := crypto.ToURLs(lc.URIs)
	if err != nil {
		return err
	}

	_, err = svc.IssueCertificate(ctx, service.IssueRequest{
		Type: pki.TypeLeaf,
		Subject: pkix.Name{
			Country:            lc.Country,
			Organization:       lc.Organization,
			OrganizationalUnit: lc.OrganizationalUnit,
			Locality:           lc.Locality,
			Province:           lc.Province,
			StreetAddress:      lc.StreetAddress,
			PostalCode:         lc.PostalCode,
			CommonName:         lc.CommonName,
		},
		SANs: pki.SANs{
			DNSNames:       lc.DNSNames,
			EmailAddresses: lc.EmailAddresses,
			IPAddresses:    netIps,
			URIs:           urls,
		},
		TTL:          lc.TTL,
		KeyID:        lc.KeyID,
		IssuerID:     lc.IssuerID,
		KeyUsages:    lc.KeyUsages,
		ExtKeyUsages: lc.ExtKeyUsages,
	})
	if err != nil {
		return err
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
