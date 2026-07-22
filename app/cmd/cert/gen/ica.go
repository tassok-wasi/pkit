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

type ICACmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"postal-code" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Key algorithm used to create the keys and sign the Certificate."`
	TTL                string   `name:"ttl" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"17280h"`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate."`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate."`
	KeyUsages          []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
	ExtKeyUsages       []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Custom extended key usages (comma-separated or multiple flags)."`
	PathLen            int      `name:"path-len" help:"Maximum Path Len of the Certificate."`

	IssuerID int64 `name:"iss" help:"Issuer Certificate ID"`
	KeyID    int64 `name:"kid" help:"ID of the Key to sign the Certificate."`
}

func (ic *ICACmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(ic.TTL)
	if err != nil {
		return fmt.Errorf("invalid TTL value: %w", err)
	}

	dbKey, err := query.GetKeyByID(ctx, ic.KeyID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(dbKey.PrivateKeyPem), []byte(dbKey.PublicKeyPem))
	if err != nil {
		return err
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, ic.IssuerID)
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

	icaCert, err := domain.IssueCertificate(domain.CertOptions{
		Type: domain.TypeIntermediate,
		Subject: pkix.Name{
			Country:            ic.Country,
			Organization:       ic.Organization,
			OrganizationalUnit: ic.OrganizationalUnit,
			Locality:           ic.Locality,
			Province:           ic.Province,
			StreetAddress:      ic.StreetAddress,
			PostalCode:         ic.PostalCode,
			CommonName:         ic.CommonName,
		},
		SANs: domain.SANs{
			DNSNames:       ic.DNSNames,
			EmailAddresses: ic.EmailAddresses,
			IPAddresses:    utils.ToNetIPs(ic.IPAddresses),
			URIs:           utils.ToURLs(ic.URIs),
		},
		TTLInHours: hours,
		KeyPair: &domain.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		},
		ParentCert: issuerCert,
		ParentKey:  issuerPrivateKey,
		Usages: &domain.KeyUsageConfig{
			KeyUsages:    utils.ParseKeyUsages(ic.KeyUsages),
			ExtKeyUsages: utils.ParseExtKeyUsages(ic.ExtKeyUsages),
		},
		PathLen: new(ic.PathLen),
	})
	if err != nil {
		return fmt.Errorf("cannot generate Intermediate CA Certificate: %w", err)
	}

	// -------------------------------- WRITING TO THE DB --------------------------------------

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: icaCert.Raw,
	})

	skidHex := hex.EncodeToString(icaCert.SubjectKeyId)
	akidHex := hex.EncodeToString(icaCert.AuthorityKeyId)

	_, err = query.CreateCertificate(ctx, base.CreateCertificateParams{
		SerialNumber:       fmt.Sprintf("%x", icaCert.SerialNumber),
		CommonName:         icaCert.Subject.CommonName,
		Type:               "INTERMEDIATE-CA",
		KeyID:              dbKey.ID,
		IssuerSerialNumber: sql.NullString{String: fmt.Sprintf("%x", issuerDBCert.SerialNumber), Valid: true},
		Skid:               skidHex,
		Akid:               akidHex,
		Status:             "ACTIVE",
		NotBefore:          icaCert.NotBefore,
		NotAfter:           icaCert.NotAfter,
		CertificatePem:     string(certPem),
	})
	if err != nil {
		return fmt.Errorf("failed to create Certificate in DB: %w", err)
	}

	log.Println("Success: successfully Created Certificate.")

	return nil
}
