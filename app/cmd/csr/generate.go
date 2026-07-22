package csr

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"log"
)

type GenerateCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"postal-code" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Key algorithm used to create the keys and sign the Certificate."`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate."`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate."`

	KeyID int64 `name:"kid" help:"ID of the Key to Generate the CSR."`
}

func (gc *GenerateCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	dbKey, err := query.GetKeyByID(ctx, gc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch Key from database: %w", err)
	}

	privateKey, _, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	signatureAlgo, err := utils.GetSignatureAlgorithm(gc.KeyType)
	if err != nil {
		return err
	}

	csrTemplate := x509.CertificateRequest{
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
		DNSNames:       gc.DNSNames,
		EmailAddresses: gc.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(gc.IPAddresses),
		URIs:           utils.ToURLs(gc.URIs),

		SignatureAlgorithm: signatureAlgo,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPem, err := utils.EncodeToPem(csr, "CERTIFICATE REQUEST")
	if err != nil {
		return err
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	_, err = query.CreateCSR(ctx, base.CreateCSRParams{
		CommonName:    csrTemplate.Subject.CommonName,
		KeyID:         dbKey.ID,
		Status:        "PENDING",
		CsrPem:        string(csrPem),
		CertificateID: sql.NullInt64{Int64: 0, Valid: false},
	})
	if err != nil {
		return fmt.Errorf("failed to create CSR in database: %w", err)
	}

	log.Println("Success: successfully Created Certificate Signing Request.")

	return nil
}
