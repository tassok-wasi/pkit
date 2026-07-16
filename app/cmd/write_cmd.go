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

	var dir string
	var err error

	// Determine deterministic path based on type
	if registry.Certificate.IsCA && subName == issName {
		baseDir, err := utils.JoinHomeDir("~/certman/certificates/roots")
		if err != nil {
			return err
		}
		dir = filepath.Join(baseDir, subName)
	} else {
		baseDir, err := utils.JoinHomeDir("~/certman/certificates/issued_by")
		if err != nil {
			return err
		}
		dir = filepath.Join(baseDir, issName, subName)
	}

	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create target certificate directory: %w", err)
	}

	certFilePath := filepath.Join(dir, subName+".cert")
	privKeyFilePath := filepath.Join(dir, subName+"_private_key.pem")
	pubKeyFilePath := filepath.Join(dir, subName+"_public_key.pem")

	if err := utils.WriteCert(certFilePath, registry.Certificate.Raw); err != nil {
		return fmt.Errorf("failed writing cert: %w", err)
	}
	if err := utils.WriteKey(privKeyFilePath, registry.PrivateKey, utils.PRIVATE, true, true); err != nil {
		return fmt.Errorf("failed writing private key: %w", err)
	}
	if err := utils.WriteKey(pubKeyFilePath, registry.PublicKey, utils.PUBLIC, false, true); err != nil {
		return fmt.Errorf("failed writing public key: %w", err)
	}

	return nil
}
