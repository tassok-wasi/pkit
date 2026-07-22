package gen

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"

	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"
)

type LeafCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"postal-code" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Key algorithm used to create the keys and sign the Certificate."`
	TTL                string   `name:"ttl" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate."`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
	ExtKeyUsages       []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Custom extended key usages (comma-separated or multiple flags)."`

	IssuerID int64 `name:"iss" help:"Issuer Certificate ID"`
	KeyID    int64 `name:"kid" help:"ID of the Key to sign the Certificate."`
}

func (lc *LeafCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(lc.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := query.GetKeyByID(ctx, lc.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch Key from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, lc.IssuerID)
	if err != nil {
		return fmt.Errorf("failed to fetch issuer Certificate from DB: %w", err)
	}
	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}

	issuerKeys, err := query.GetKeyByID(ctx, issuerDBCert.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	issuerPrivateKey, _, err := utils.ParseKeys([]byte(issuerKeys.PrivateKeyPem), []byte(issuerKeys.PublicKeyPem))
	if err != nil {
		return err
	}

	leafCert, err := domain.IssueCertificate(domain.CertOptions{
		Type: domain.TypeLeaf,
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
		SANs: domain.SANs{
			DNSNames:       lc.DNSNames,
			EmailAddresses: lc.EmailAddresses,
			IPAddresses:    utils.ToNetIPs(lc.IPAddresses),
			URIs:           utils.ToURLs(lc.URIs),
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(lc.KeyUsages),
			ExtKeyUsages: utils.ParseExtKeyUsages(lc.ExtKeyUsages),
		},
		PathLen: nil,
	})
	if err != nil {
		return fmt.Errorf("failed to generate Leaf Certificate: %w", err)
	}

	// ----------------------------- WRITING TO THE DATABASE -------------------------------------

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	skidHex := hex.EncodeToString(leafCert.SubjectKeyId)
	akidHex := hex.EncodeToString(leafCert.AuthorityKeyId)

	_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", leafCert.SerialNumber),
		CommonName:         leafCert.Subject.CommonName,
		Type:               "LEAF",
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: fmt.Sprintf("%x", issuerCert.SerialNumber), Valid: false},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		NotBefore:          leafCert.NotBefore,
		NotAfter:           leafCert.NotAfter,
		CertificatePem:     string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in DB: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
