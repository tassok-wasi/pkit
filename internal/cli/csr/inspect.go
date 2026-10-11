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
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/tassok-wasi/pkit/internal/service"
)

type InspectCmd struct {
	ID int64 `arg:"" help:"Database ID of the CSR to inspect."`
}

func (ic *InspectCmd) Run(ctx context.Context, svc *service.Service) error {
	dbCsr, err := svc.GetCSR(ctx, ic.ID)
	if err != nil {
		return err
	}

	csr, err := svc.GetParsedCSR(ctx, ic.ID)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "FIELD\tVALUE")
	fmt.Fprintln(w, "-----\t-----")
	fmt.Fprintf(w, "ID\t%d\n", dbCsr.ID)
	fmt.Fprintf(w, "Status\t%s\n", dbCsr.Status)
	fmt.Fprintf(w, "Common Name (CN)\t%s\n", csr.Subject.CommonName)

	// Display Subject Details if present
	if len(csr.Subject.Organization) > 0 {
		fmt.Fprintf(w, "Organization (O)\t%s\n", strings.Join(csr.Subject.Organization, ", "))
	}
	if len(csr.Subject.OrganizationalUnit) > 0 {
		fmt.Fprintf(w, "Organizational Unit (OU)\t%s\n", strings.Join(csr.Subject.OrganizationalUnit, ", "))
	}
	if len(csr.Subject.Country) > 0 {
		fmt.Fprintf(w, "Country (C)\t%s\n", strings.Join(csr.Subject.Country, ", "))
	}

	// Public Key Details
	keyInfo := "Unknown"
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		keyInfo = fmt.Sprintf("RSA (%d bits)", pub.N.BitLen())
	default:
		keyInfo = fmt.Sprintf("%T", pub)
	}
	fmt.Fprintf(w, "Public Key\t%s\n", keyInfo)
	fmt.Fprintf(w, "Signature Algorithm\t%s\n", csr.SignatureAlgorithm.String())

	// Subject Alternative Names (SANs)
	if len(csr.DNSNames) > 0 {
		fmt.Fprintf(w, "DNS SANs\t%s\n", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Fprintf(w, "IP SANs\t%s\n", strings.Join(ips, ", "))
	}
	if len(csr.EmailAddresses) > 0 {
		fmt.Fprintf(w, "Email SANs\t%s\n", strings.Join(csr.EmailAddresses, ", "))
	}

	// Linked Certificate Serial (if already signed)
	if dbCsr.CertificateID.Valid {
		serialNumber, err := svc.GetCertificateSerialNumber(ctx, dbCsr.CertificateID.Int64)
		if err != nil {
			return fmt.Errorf("failed to get Certificate Serial Number from db: %w", err)
		}
		if serialNumber != "" {
			fmt.Fprintf(w, "Signed Cert Serial\t%s\n", serialNumber)
		}
	}

	w.Flush()

	return nil
}
