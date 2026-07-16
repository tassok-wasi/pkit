# Code documentation for `certman`

*Generated from: `/home/tassok/CLI/certman`*

**Extensions included:** .go

---

## `app/cmd/ca_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/ca_cmd.go`
- **Size:** 5307 bytes

```go
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
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
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		log.Fatalf("unsupported key type: %s", c.KeyType)
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
		log.Fatal("cannot generate CA Certificate")
	}

	registry.Certificate = caCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
```

---

## `app/cmd/inter_ca_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/inter_ca_cmd.go`
- **Size:** 7717 bytes

```go
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"

	"charm.land/huh/v2"
)

type InterCACmd struct {
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
	ParentCertPath     string   `name:"parent-cert" required:"" type:"path" help:"Parent Certificate Path for signing the Intermediate Certificate."`
	ParentPrivkeyPath  string   `name:"parent-priv-key" required:"" type:"path" help:"Parent Private Key for signing the Intermediate Certificate."`
}

func InterCAPrompt(initial *InterCACmd) (*InterCACmd, error) {
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
	return &InterCACmd{
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

func (c *InterCACmd) Run(registry *DataRegistry) error {
	finalConfig := c
	if c.IT {
		promptResult, err := InterCAPrompt(c)
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

	interCaCert, err := domain.GetIntermediate(pkix.Name{
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

	registry.Certificate = interCaCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
```

---

## `app/cmd/leaf_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/leaf_cmd.go`
- **Size:** 7657 bytes

```go
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
```

---

## `app/cmd/read_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/read_cmd.go`
- **Size:** 767 bytes

```go
package cmd

import (
	"certman/app/utils"
	"errors"
	"fmt"
)

type ReadCmd struct {
	Path     string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert,.key,.pem) format."`
	FileType string `name:"type" short:"t" required:"" type:"path" enum:"cert,key" help:"File type to read."`
}

func (rc *ReadCmd) Run() error {
	if rc.FileType == "cert" {
		cert, err := utils.ReadFile(rc.Path)
		if err != nil {
			return fmt.Errorf("file does not contains valid certificate")
		}

		fmt.Println(string(cert))
	}
	if rc.FileType == "key" {
		key, err := utils.ReadFile(rc.Path)
		if err != nil {
			return fmt.Errorf("file does not contains valid key")
		}

		fmt.Println(string(key))
	}

	return errors.New("unknown file type")
}
```

---

## `app/cmd/registry.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/registry.go`
- **Size:** 129 bytes

```go
package cmd

import "crypto/x509"

type DataRegistry struct {
	Certificate *x509.Certificate
	PrivateKey  any
	PublicKey   any
}
```

---

## `app/cmd/write_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/write_cmd.go`
- **Size:** 2654 bytes

```go
package cmd

import (
	"certman/app/utils"
	"fmt"
	"os"
	"path/filepath"
)

type WriteCmd struct {
	CA             CACmd      `cmd:"" help:"Generates CA Certificate."`
	IntermediateCA InterCACmd `cmd:"" help:"Generates Intermediate CA Certificate."`
	Leaf           LeafCmd    `cmd:"" help:"Generates Leaf Certificate."`
}

func (wc *WriteCmd) Run(registry *DataRegistry) error {
	subName := utils.ToSnakeCase(registry.Certificate.Subject.CommonName)
	issName := utils.ToSnakeCase(registry.Certificate.Issuer.CommonName)

	if registry.Certificate.IsCA && subName == issName {
		dir, err := utils.JoinHomeDir("~/certman/certificates/" + subName)
		if err != nil {
			return err
		}
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("cannot create directory for root ca: %w", err)
		}

		certFilePath := filepath.Join(dir, subName+".cert")
		utils.WriteCert(certFilePath, registry.Certificate.Raw)

		privKeyFilePath := filepath.Join(dir, subName+"_private_key.pem")
		utils.WriteKey(privKeyFilePath, registry.PrivateKey, utils.PRIVATE, true)

		pubKeyFilePath := filepath.Join(dir, subName+"_public_key.pem")
		utils.WriteKey(pubKeyFilePath, registry.PublicKey, utils.PUBLIC, false)

		return nil
	} else if registry.Certificate.IsCA && subName != issName {
		fullPath, err := utils.JoinHomeDir("~/certman/certificates")
		if err != nil {
			return err
		}
		foundPath, err := utils.FindDir(fullPath, issName)
		if err != nil {
			return err
		}

		dir := foundPath + "/" + subName
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("cannot create directory for intermediate ca: %w", err)
		}

		certFilePath := filepath.Join(dir, subName+".cert")
		utils.WriteCert(certFilePath, registry.Certificate.Raw)

		privKeyFilePath := filepath.Join(dir, subName+"_private_key.pem")
		utils.WriteKey(privKeyFilePath, registry.PrivateKey, utils.PRIVATE, true)

		pubKeyFilePath := filepath.Join(dir, subName+"_public_key.pem")
		utils.WriteKey(pubKeyFilePath, registry.PublicKey, utils.PUBLIC, false)

		return nil
	} else {
		fullPath, err := utils.JoinHomeDir("~/certman/certificates")
		if err != nil {
			return err
		}
		dir, err := utils.FindDir(fullPath, issName)
		if err != nil {
			return err
		}

		certFilePath := filepath.Join(dir, subName+".cert")
		utils.WriteCert(certFilePath, registry.Certificate.Raw)

		privKeyFilePath := filepath.Join(dir, subName+"_private_key.pem")
		utils.WriteKey(privKeyFilePath, registry.PrivateKey, utils.PRIVATE, true)

		pubKeyFilePath := filepath.Join(dir, subName+"_public_key.pem")
		utils.WriteKey(pubKeyFilePath, registry.PublicKey, utils.PUBLIC, false)

		return nil
	}
}
```

---

## `app/domain/cert.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/cert.go`
- **Size:** 4146 bytes

```go
package domain

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"certman/app/utils"
)

// GetBaseTemplate generates the basic certificate scaffolding.
func GetBaseTemplate(subject pkix.Name, serialNumber *big.Int, ttlInHour int, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ttlInHour) * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true, // Crucial for CA validation
	}
}

func GetCA(subject pkix.Name, ttlInHour int, keyPair *KeyPair) (*x509.Certificate, error) {
	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	// Self-signed CA: Subject Key ID and Authority Key ID match
	skid, err := generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = skid
	template.AuthorityKeyId = skid

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	return caCert, nil
}

func GetIntermediate(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, errors.New("invalid parent certificate: parent must be a valid CA")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// MaxPathLen constraints
	template.MaxPathLen = 0
	template.MaxPathLenZero = true // This intermediate can only sign leaf certs, not more CAs

	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	interBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate intermediate certificate: %w", err)
	}

	interCaCert, err := x509.ParseCertificate(interBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse intermediate certificate: %w", err)
	}

	return interCaCert, nil
}

func GetLeaf(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, fmt.Errorf("invalid parent certificate: leaf must be signed by a CA/Intermediate")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, false)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	leafBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse leaf certificate: %w", err)
	}

	return leafCert, nil
}
```

---

## `app/domain/constants.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/constants.go`
- **Size:** 575 bytes

```go
package domain

import (
	"crypto/x509"
	"net"
	"net/url"
)

type KeyType string

const (
	RSA_2048   KeyType = "rsa-2048"
	RSA_4096   KeyType = "rsa-4096"
	ECDSA_P224 KeyType = "ecdsa-224"
	ECDSA_P256 KeyType = "ecdsa-256"
	ECDSA_P384 KeyType = "ecdsa-384"
	ECDSA_P521 KeyType = "ecdsa-521"
	ED25519    KeyType = "ed25519"
)

type KeyPair struct {
	PrivateKey any
	PublicKey  any
}

type Certificate struct {
	Cert *x509.Certificate
	Keys *KeyPair
}

type SANs struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}
```

---

## `app/domain/helpers.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/helpers.go`
- **Size:** 2033 bytes

```go
package domain

import (
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"fmt"

	"certman/app/utils"
)

// Helper to get KeyPair based on the type
func GetKey(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case RSA_2048:
		privKey, pubKey, err := utils.GetRSAKey(2048)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case RSA_4096:
		privKey, pubKey, err := utils.GetRSAKey(4096)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P224:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P224())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P256:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P256())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P384:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P384())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P521:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P521())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ED25519:
		privKey, pubKey, err := utils.GetED25519Key()
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// Helper to generate a Subject Key Identifier from a public key
func generateSKID(pubKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID using public key: %w", err)
	}
	// Classic RFC 5280 method 1: SHA-1 hash of the value of the BIT STRING subjectPublicKey
	hasher := sha1.New()
	hasher.Write(der)
	return hasher.Sum(nil), nil
}
```

---

## `app/utils/cipher.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/cipher.go`
- **Size:** 1183 bytes

```go
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(plaintext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot generate secure nonce: %w", err)
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("cipher is too short: %v", len(ciphertext))
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, actualCiphertext, nil)
}
```

---

## `app/utils/hash.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/hash.go`
- **Size:** 2004 bytes

```go
package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// const (
// 	argonTime    = 1
// 	argonMemory  = 64 * 1024
// 	argonThreads = 4
// 	argonKeyLen  = 32
// 	argonSaltLen = 16
// )

type Hasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

func NewHasher(time, memory uint32, threads uint8, keyLen, saltLen uint32) *Hasher {
	return &Hasher{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
}

func (a *Hasher) Hash(password []byte) ([]byte, error) {
	salt := make([]byte, a.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.Memory, a.Time, a.Threads, b64Salt, b64Hash)
	return []byte(encoded), nil
}

func (a *Hasher) Verify(password []byte, encodedHash []byte) (bool, error) {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid argon2id string format")
	}

	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("invalid argon2id parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	hash := argon2.IDKey(password, salt, time, memory, threads, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}
```

---

## `app/utils/key.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/key.go`
- **Size:** 1497 bytes

```go
package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

func GetRSAKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate rsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ecdsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetED25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ed25519 key: %v", err)
	}
	return privKey, pubKey, nil
}

func ParseKey(privKey, pubKey []byte) (any, any, error) {
	parsedPub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse PKIX public key: %w", err)
	}

	if parsedPriv, err := x509.ParsePKCS8PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParsePKCS1PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParseECPrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}

	return nil, nil, errors.New("unknown key type")
}
```

---

## `app/utils/keyring.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/keyring.go`
- **Size:** 1477 bytes

```go
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in Fedora's keyring
func InitMasterKey() error {
	// Check if a key already exists to prevent accidental overwriting
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		return errors.New("application is already initialized with a master key")
	}

	// Generate a secure 32-byte (256-bit) AES key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("cannot generate secure bytes: %w", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	// Save to OS Keyring
	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		return fmt.Errorf("cannot store key in OS keyring: %w", err)
	}
	return nil
}

// GetMasterKey silently retrieves the key from the OS keyring for cryptography
func GetMasterKey() ([]byte, error) {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("app not initialized. Please run the init command first")
		}
		return nil, fmt.Errorf("cannot fetch key from OS keyring: %v", err)
	}

	// Decode back to raw bytes for AES-GCM encryption/decryption
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
```

---

## `app/utils/read.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/read.go`
- **Size:** 1808 bytes

```go
package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadFile(filePath string) ([]byte, error) {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return nil, err
	}

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file data: %w", err)
	}

	return fileBytes, nil
}

// ReadCert reads file and returns the x509.Certificate formatted cert
// filePath can be linux path, relative path, absolute path or just file name
func ReadCert(filePath string) (*x509.Certificate, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cert: %v", err)
	}

	return cert, nil
}

// ReadKey reads file and returns the pkcs#8 for private key and pkix for public key
// filePath can be linux path, relative path, absolute path or just file name
func ReadKey(filePath string) (any, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file does not contains valid key")
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("file %v does not contain valid private or public key", filePath)
}
```

---

## `app/utils/util.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/util.go`
- **Size:** 3168 bytes

```go
package utils

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("skipping invalid IP string: %s\n", netIP)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToURL(s string) (*url.URL, error) {
	parsedUrl, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedUrl, nil
}

func ToURLs(urls []string) []*url.URL {
	var urlURLs []*url.URL

	for _, url := range urls {
		u, err := ToURL(url)
		if err != nil {
			log.Printf("skipping invalid URL string: %s\n", u)
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs
}

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// FindDir walks rootDir to find targetDirName.
func FindDir(rootDir, targetDirName string) (string, error) {
	var foundPath string

	// Walk the directory tree
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Prevent panicking on permission errors, just skip those directories
			return nil
		}

		if d.IsDir() && d.Name() == targetDirName {
			foundPath = path
			// Return filepath.SkipDir to stop searching once we find the first match
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("cannot walk path: %w", err)
	}

	if foundPath == "" {
		return "", fmt.Errorf("target directory '%s' not found", targetDirName)
	}

	return foundPath, nil
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}
```

---

## `app/utils/write.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/write.go`
- **Size:** 2347 bytes

```go
package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type KeyType int

const (
	PUBLIC KeyType = iota
	PRIVATE
)

// WriteCert saves the certificate bytes into a standard PEM encoded certificate file
// filePath can be linux path, relative path, absolute path or just file name
func WriteCert(filePath string, certBytes []byte) {
	// Certificates are public data, standard 0644 permissions are fine
	write(filePath, "CERTIFICATE", certBytes, 0o644)
}

// WriteKey takes a concrete key (e.g., *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
// and dynamically handles legacy or PKCS#8 formatting.
func WriteKey(filePath string, key any, keyType KeyType, usePKCS8 bool) {
	if keyType == PUBLIC {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			log.Fatalf("cannot marshal public key: %v", err)
		}
		write(filePath, "PUBLIC KEY", pubBytes, 0o644)
		return
	}

	// For PRIVATE keys:
	var blockType string
	var privBytes []byte
	var err error

	if usePKCS8 {
		blockType = "PRIVATE KEY"
		privBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			log.Fatalf("cannot marshal to PKCS#8: %v", err)
		}
	} else {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blockType = "RSA PRIVATE KEY"
			privBytes = x509.MarshalPKCS1PrivateKey(k)
		case *ecdsa.PrivateKey:
			blockType = "EC PRIVATE KEY"
			privBytes, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				log.Fatalf("cannot marshal EC key: %v", err)
			}
		default:
			blockType = "PRIVATE KEY"
			privBytes, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				log.Fatalf("cannot marshal to PKCS#8: %v", err)
			}
		}
	}

	write(filePath, blockType, privBytes, 0o600)
}

// write is a generic helper to write PEM blocks to disk
func write(filePath string, blockType string, bytes []byte, perm os.FileMode) error {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("cannot open %s for writing: %v", path, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
	if err != nil {
		return fmt.Errorf("cannot write to the file : %v", err)
	}

	log.Printf("successfully created %s\n", path)
	return nil
}
```

---

## `main.go`

- **Full path:** `/home/tassok/CLI/certman/main.go`
- **Size:** 621 bytes

```go
package main

import (
	"certman/app/cmd"
	"log"
	"os"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Registry *cmd.DataRegistry `kong:"-"`

	Write cmd.WriteCmd `cmd:"" help:"Writes Certificate and it's keys into a specified file structure."`
	Read  cmd.ReadCmd  `cmd:"" help:"Reads a Certificate or a specific Key from a file location"`
}

func main() {
	registry := &cmd.DataRegistry{}

	cli := CLI{Registry: registry}

	ctx := kong.Parse(&cli, kong.Name("certman"), kong.Description("A Certificate Management Toolkit"), kong.Bind(registry))

	err := ctx.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
```

---


*Total files processed: 17*
