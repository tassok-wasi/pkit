package cmd

import (
	"certman/app/domain"
	"certman/app/utils"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"strconv"
	"strings"

	"charm.land/huh/v2"
)

type LeafCmd struct {
	CommonName         string   `name:"common-name" help:"Common Name of the Certificate."`
	Country            []string `name:"country" help:"Country names of the Certificate."`
	Organization       []string `name:"org" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"province" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"post" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to crear the keys and sign the Certificate."`
	TTL                int      `name:"ttl" help:"ttl in Hours."`
	DNSNames           []string `name:"dns-names" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email-addrs" help:"EmailAddresses of the Certificate"`
	IPAddresses        []string `name:"ip-addrs" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uris" help:"URIs of the Certificate"`
	IT                 bool     `name:"it" help:"Bypass the flags and provide input via interactive prompt"`
	ParentCertPath     string   `name:"parent-cert" type:"path" help:"Parent Certificate Path for signing the Intermediate Certificate."`
	ParentPrivkeyPath  string   `name:"parent-priv-key" type:"path" help:"Parent Private Key for signing the Intermediate Certificate."`
}

func LeafPrompt(initial *LeafCmd) (*LeafCmd, error) {
	var (
		cn             = initial.CommonName
		countries      = strings.Join(initial.Country, ", ")
		orgs           = strings.Join(initial.Organization, ", ")
		units          = strings.Join(initial.OrganizationalUnit, ", ")
		localities     = strings.Join(initial.Locality, ", ")
		provinces      = strings.Join(initial.Province, ", ")
		streets        = strings.Join(initial.StreetAddress, ", ")
		posts          = strings.Join(initial.PostalCode, ", ")
		keyType        = initial.KeyType
		dnsNames       = strings.Join(initial.DNSNames, ", ")
		emailAddresses = strings.Join(initial.EmailAddresses, ", ")
		ipAddresses    = strings.Join(initial.IPAddresses, ", ")
		uris           = strings.Join(initial.URIs, ", ")
		ttlStr         string
	)

	if initial.TTL > 0 {
		ttlStr = strconv.Itoa(initial.TTL)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Common Name").Value(&cn).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("common name cannot be left blank")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("Key Type").
				Options(
					huh.NewOption("RSA 2048", "rsa-2048"),
					huh.NewOption("RSA 4096", "rsa-4096"),
					huh.NewOption("ECDSA 224", "ecdsa-224"),
					huh.NewOption("ECDSA 256", "ecdsa-256"),
					huh.NewOption("ECDSA 384", "ecdsa-384"),
					huh.NewOption("ECDSA 521", "ecdsa-521"),
					huh.NewOption("Ed25519", "ed25519"),
				).Value(&keyType),
			huh.NewInput().Title("TTL (Hours)").Value(&ttlStr).Validate(func(s string) error {
				_, err := strconv.Atoi(s)
				if err != nil {
					return fmt.Errorf("must be a valid numeric duration integer above 0")
				}
				return nil
			}),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
			huh.NewInput().Title("DNS Names (comma separated)").Value(&dnsNames),
			huh.NewInput().Title("Email Addresses (comma separated)").Value(&emailAddresses),
			huh.NewInput().Title("IP Addresses (comma separated)").Value(&ipAddresses),
			huh.NewInput().Title("URIs (comma separated)").Value(&uris),
		),
	)

	// Step 3: Launch form rendering
	if err := form.Run(); err != nil {
		return nil, err
	}

	// Step 4: Export terminal text cleanly back into a fresh struct instance
	parsedTTL, _ := strconv.Atoi(ttlStr)
	return &LeafCmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		DNSNames:           utils.SplitCSV(dnsNames),
		EmailAddresses:     utils.SplitCSV(emailAddresses),
		IPAddresses:        utils.SplitCSV(ipAddresses),
		URIs:               utils.SplitCSV(uris),
		KeyType:            keyType,
		TTL:                parsedTTL,
		IT:                 true,
	}, nil
}

func (c *LeafCmd) Run(registry *DataRegistry) error {
	finalConfig := c
	if c.IT {
		promptResult, err := LeafPrompt(c)
		if err != nil {
			log.Fatalf("prompt cancelled: %v", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type")
		}
		if finalConfig.TTL <= 0 {
			return fmt.Errorf("missing required flag: --ttl must be greater than 0")
		}
		if finalConfig.ParentCertPath == "" {
			return fmt.Errorf("missing required flag: --parent-cert")
		}
		if finalConfig.ParentPrivkeyPath == "" {
			return fmt.Errorf("missing required flag: --parent-priv-key")
		}
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		log.Fatalf("unsupported key type: %s", c.KeyType)
	}

	parentCert, err := utils.ReadCert(finalConfig.ParentCertPath)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid certificate", finalConfig.ParentCertPath)
	}
	parentPrivKey, err := utils.ReadKey(finalConfig.ParentPrivkeyPath)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid private key", finalConfig.ParentPrivkeyPath)
	}

	parent := domain.Certificate{
		Cert: parentCert,
		Keys: &domain.KeyPair{
			PrivateKey: parentPrivKey,
		},
	}

	leafCert, err := domain.GetLeaf(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, domain.SANs{
		DNSNames:       finalConfig.DNSNames,
		EmailAddresses: finalConfig.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(finalConfig.IPAddresses),
		URIs:           utils.ToURLs(finalConfig.URIs),
	}, finalConfig.TTL, keyPair, &parent)
	if err != nil {
		log.Fatal("cannot generate Intermediate CA Certificate")
	}

	registry.Certificate = leafCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
