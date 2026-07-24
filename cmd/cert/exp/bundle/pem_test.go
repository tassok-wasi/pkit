// Copyright 2026 Tassok Imam Wasi

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGetPEMBundle(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		privKey  any
		leafCert *x509.Certificate
		chain    []*x509.Certificate
		wantErr  bool
	}{
		{
			name:     "valid all params",
			privKey:  priv,
			leafCert: cert,
			chain:    []*x509.Certificate{cert},
			wantErr:  false,
		},
		{
			name:     "nil privKey",
			privKey:  nil,
			leafCert: cert,
			chain:    nil,
			wantErr:  false,
		},
		{
			name:     "nil leaf",
			privKey:  priv,
			leafCert: nil,
			chain:    []*x509.Certificate{cert},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemBytes, err := GetPEMBundle(tt.privKey, tt.leafCert, tt.chain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPEMBundle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Just check it's valid PEM
				remaining := pemBytes
				for len(remaining) > 0 {
					block, rest := pem.Decode(remaining)
					if block == nil {
						break
					}
					remaining = rest
				}
			}
		})
	}
}
