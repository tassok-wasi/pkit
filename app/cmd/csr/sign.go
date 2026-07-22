package csr

import (
	"certman/app/domain"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
)

type SignCmd struct {
	ID   int64  `arg:"" help:"ID of the CSR to Sign."`
	Type string `name:"type" required:"" help:"Type of the Certificate e.g., CA, INTERMEDIATE, LEAF"`
	TTL  string `name:"ttl" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`

	KeyUsages    []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
	ExtKeyUsages []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Custom extended key usages (comma-separated or multiple flags)."`
	PathLen      int      `name:"path-len" help:"Maximum Path length of the Certificate. Omit for CAs and Leaves"`

	IssuerID int64 `name:"iss" help:"Issuer Certificate ID"`
}

func (sc *SignCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(sc.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbCsr, err := query.GetCSRByID(ctx, sc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch CSR from DB: %w", err)
	}

	csrBlock, _ := pem.Decode([]byte(dbCsr.CsrPem))
	if csrBlock == nil {
		return errors.New("failed to decode CSR pem block")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, int64(sc.IssuerID))
	if err != nil {
		return fmt.Errorf("failed to fetch Certificate from DB: %w", err)
	}
	issuerDBKeys, err := query.GetKeyByID(ctx, issuerDBCert.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer keys from DB: %w", err)
	}

	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}
	issuerPrivKey, _, err := utils.ParseKeys([]byte(issuerDBKeys.PrivateKeyPem), []byte(issuerDBKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	cert, err := domain.IssueCertificate(domain.CertOptions{
		Type:    domain.CertType(sc.Type),
		Subject: csr.Subject,
		SANs: domain.SANs{
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			EmailAddresses: csr.EmailAddresses,
			URIs:           csr.URIs,
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PublicKey: csr.PublicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(sc.KeyUsages),
			ExtKeyUsages: utils.ParseExtKeyUsages(sc.ExtKeyUsages),
		},
		PathLen: new(sc.PathLen),
	})
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	certPemBytes, err := utils.EncodeToPem(cert.Raw, "CERTIFICATE")
	if err != nil {
		return err
	}

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       cert.SerialNumber.String(),
			CommonName:         cert.Subject.CommonName,
			Type:               sc.Type,
			KeyID:              dbCsr.KeyID,
			IssuerSerialNumber: sql.NullString{String: issuerCert.SerialNumber.String(), Valid: true},
			Skid:               hex.EncodeToString(cert.SubjectKeyId),
			Akid:               hex.EncodeToString(cert.AuthorityKeyId),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			CertificatePem:     certPemBytes,
		})
		if err != nil {
			return fmt.Errorf("failed to create Certificate in DB: %w", err)
		}

		err = txQuerier.UpdateCSRStatus(ctx, base.UpdateCSRStatusParams{
			Status:        "SIGNED",
			CertificateID: sql.NullInt64{Int64: dbCsr.ID, Valid: true},
			CommonName:    dbCsr.CommonName,
		})
		if err != nil {
			return fmt.Errorf("failed to update csr status: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Succes: successfully created Certificate.")

	return nil
}
