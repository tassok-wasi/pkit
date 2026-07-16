package cmd

import (
	"certman/app/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"
)

type VerifyCmd struct {
	Cert VerifyCertCmd `cmd:"" help:"Verify Certificate."`
	Pair VerifyKeyCmd  `cmd:"" help:"Verify Key Pair with Certifiate."`
}

type VerifyCertCmd struct {
	Path   string `name:"path" short:"p" type:"path" required:"" help:"Path of the Certificate that needs to be verified."`
	Issuer string `name:"issuer" short:"i" type:"path" required:"" help:"Path of the Issuer Certificate that will be used to verify the Certificate."`
	Root   string `name:"root" short:"r" type:"path" help:"Path of the Root Certificate. If Issuer is an Intermediate then this Root path is needed."`
}

func (vc *VerifyCertCmd) Run() error {
	cert, err := utils.ReadCert(vc.Path)
	if err != nil {
		return err
	}
	issuerCert, err := utils.ReadCert(vc.Issuer)
	if err != nil {
		return err
	}
	rootCert, err := utils.ReadCert(vc.Root)
	if err != nil {
		return err
	}

	rootPool := x509.NewCertPool()
	intermediatesPool := x509.NewCertPool()

	isRoot := issuerCert.CheckSignatureFrom(issuerCert) == nil

	if isRoot {
		rootPool.AddCert(issuerCert)
	} else {
		intermediatesPool.AddCert(issuerCert)

		if vc.Root == "" {
			return errors.New("the provided issuer is an intermediate certificate; you must provide the --root path to verify it")
		}

		rootPool.AddCert(rootCert)
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatesPool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	log.Println("Success: Certificate chain is valid and trusted by your custom Root CA.")
	return nil
}

type VerifyKeyCmd struct {
	Cert string `name:"cert" short:"c" type:"path" help:"Path of the Certificate of which key will be verified."`
	Key  string `name:"key" short:"k" type:"path" help:"Path of the Private Key file that needs to be verified."`
}

func (vc *VerifyKeyCmd) Run() error {
	cert, err := utils.ReadCert(vc.Cert)
	if err != nil {
		return nil
	}
	privateKey, err := utils.ReadKey(vc.Key)
	if err != nil {
		return err
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an RSA public key, but the private key is not RSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: RSA private key does not belong to this certificate")
		}

	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an ECDSA public key, but the private key is not ECDSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: ECDSA private key does not belong to this certificate")
		}

	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an Ed25519 public key, but the private key is not Ed25519")
		}
		// For Ed25519, the public key is explicitly embedded inside the private key structure
		privPub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || !pub.Equal(privPub) {
			return errors.New("cryptographic mismatch: Ed25519 private key does not belong to this certificate")
		}

	default:
		return fmt.Errorf("unsupported public key algorithm type: %T", cert.PublicKey)
	}

	log.Println("Success: The private key perfectly matches the certificate public key.")
	return nil
}
