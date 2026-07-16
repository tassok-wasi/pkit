package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"

	"charm.land/huh/v2"
)

type CACmd struct {
	CommonName         string   `name:"common-name" help:"Common Name of the Certificate."`
	Country            []string `name:"country" help:"Country names of the Certificate."`
	Organization       []string `name:"org" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"province" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"post" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"key-type specifies the Key will be used to sign the Certificate."`
	TTL                int      `name:"ttl" help:"ttl in Hours."`
	IT                 bool     `name:"it" help:"Bypass the flags and provide input via interactive prompt"`
}

func CAPrompt(initial *CACmd) (*CACmd, error) {
	var (
		cn         = initial.CommonName
		countries  = strings.Join(initial.Country, ", ")
		orgs       = strings.Join(initial.Organization, ", ")
		units      = strings.Join(initial.OrganizationalUnit, ", ")
		localities = strings.Join(initial.Locality, ", ")
		provinces  = strings.Join(initial.Province, ", ")
		streets    = strings.Join(initial.StreetAddress, ", ")
		posts      = strings.Join(initial.PostalCode, ", ")
		keyType    = initial.KeyType
		ttlStr     string
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
		),
	)

	// Step 3: Launch form rendering
	if err := form.Run(); err != nil {
		return nil, err
	}

	// Step 4: Export terminal text cleanly back into a fresh struct instance
	parsedTTL, _ := strconv.Atoi(ttlStr)
	return &CACmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		KeyType:            keyType,
		TTL:                parsedTTL,
		IT:                 true,
	}, nil
}

func (c *CACmd) Run(registry *DataRegistry) error {
	finalConfig := c
	if c.IT {
		promptResult, err := CAPrompt(c)
		if err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
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
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", c.KeyType)
	}

	caCert, err := domain.GetCA(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, finalConfig.TTL, keyPair)
	if err != nil {
		return fmt.Errorf("cannot generate CA Certificate")
	}

	registry.Certificate = caCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
