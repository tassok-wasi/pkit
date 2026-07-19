package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"
)

type VerifyCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected and one must be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected and one must be selected."`
}

func (vc *VerifyCmd) Run(ctx context.Context, query base.Querier) error {
	var cert *x509.Certificate
	var issuerCert *x509.Certificate
	var rootCert *x509.Certificate

	if vc.SerialNumber != "" && vc.CommonName == "" {
		dbCert, err := query.GetCertificateBySN(ctx, vc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else if vc.SerialNumber == "" && vc.CommonName != "" {
		dbCert, err := query.GetCertificateByCN(ctx, vc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
		cert, err = utils.ParseCertificate([]byte(dbCert.CertificatePem))
		if err != nil {
			return err
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	if cert.Issuer.SerialNumber != "" {
		dbIssuerCert, err := query.GetCertificateBySN(ctx, cert.Issuer.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get issuer Certificate: %w", err)
		}
		issuerCert, err = utils.ParseCertificate([]byte(dbIssuerCert.CertificatePem))
		if err != nil {
			return err
		}
	}

	if issuerCert != nil {
		rootCert = issuerCert
		for {
			if rootCert.CheckSignatureFrom(rootCert) == nil {
				break
			}
			if rootCert.Issuer.SerialNumber == "" {
				break
			}
			dbRootCert, err := query.GetCertificateBySN(ctx, rootCert.Issuer.SerialNumber)
			if err != nil {
				return fmt.Errorf("failed to get next chain certificate: %w", err)
			}
			nextCert, err := utils.ParseCertificate([]byte(dbRootCert.CertificatePem))
			if err != nil {
				return err
			}
			if nextCert.SerialNumber.String() == rootCert.SerialNumber.String() {
				break
			}
			rootCert = nextCert
		}
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		log.Printf("Warning: Certificate is not valid yet! (Starts: %s)\n", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		log.Printf("Warning: Certificate is EXPIRED! (Expired on: %s)\n", cert.NotAfter.Format(time.RFC3339))
	} else if cert.NotAfter.Sub(now) < (30 * 24 * time.Hour) {
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		log.Printf("Warning: Certificate expires soon in %d days! (Expires on: %s)\n", daysRemaining, cert.NotAfter.Format(time.RFC3339))
	}

	rootPool := x509.NewCertPool()
	issuersPool := x509.NewCertPool()

	if issuerCert == nil {
		return errors.New("unable to verify chain: issuer certificate not found in database")
	}
	isRoot := issuerCert.CheckSignatureFrom(issuerCert) == nil

	if isRoot {
		rootPool.AddCert(issuerCert)
	} else {
		issuersPool.AddCert(issuerCert)
		rootPool.AddCert(rootCert)
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: issuersPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	log.Println("Success: Certificate chain is valid and trusted!")
	log.Printf("Verified Chain depth: %d certificates in the trust chain.\n", len(chains[0]))

	return nil
}
