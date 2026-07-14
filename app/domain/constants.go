package domain

import (
	"crypto/x509"
	"net"
	"net/url"
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
