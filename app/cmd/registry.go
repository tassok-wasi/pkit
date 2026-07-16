package cmd

import "crypto/x509"

type DataRegistry struct {
	Certificate *x509.Certificate
	PrivateKey  any
	PublicKey   any
}
