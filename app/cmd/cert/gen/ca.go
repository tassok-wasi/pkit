package gen

import (
	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
)

type CACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"postal-code" help:"PostalCode of the Certificate."`
	TTL                string   `name:"ttl" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"86400h"`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`

	KeyID int64 `name:"kid" help:"ID of the Key to sign the Certificate."`
}

func (cc *CACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(cc.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := query.GetKeyByID(ctx, cc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get Key from database: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	caCert, err := domain.IssueCertificate(domain.CertOptions{
		Type: domain.TypeRootCA,
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
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: nil,
		ParentKey:  nil,
		Usages: &domain.KeyUsageConfig{
			KeyUsages: utils.ParseKeyUsages(cc.KeyUsages),
		},
		PathLen: nil,
	})
	if err != nil {
		return fmt.Errorf("failed to generate CA Certificate: %w", err)
	}

	// ------------------------- WRITING TO THE DATABASE ------------------------------

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	var skidHex, akidHex string
	if len(caCert.SubjectKeyId) > 0 {
		skidHex = hex.EncodeToString(caCert.SubjectKeyId)
	}
	if len(caCert.AuthorityKeyId) > 0 {
		akidHex = hex.EncodeToString(caCert.AuthorityKeyId)
	} else {
		// Fallback for self-signed root anchors
		akidHex = skidHex
	}

	_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", caCert.SerialNumber),
		CommonName:         caCert.Subject.CommonName,
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: "", Valid: false},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		NotBefore:          caCert.NotBefore,
		NotAfter:           caCert.NotAfter,
		CertificatePem:     string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in database: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
