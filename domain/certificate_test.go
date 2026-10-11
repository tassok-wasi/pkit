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

package domain

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/tassok-wasi/pkit/utils"
)

func TestIssueCertificate(t *testing.T) {
	testCases := []struct {
		name    string
		opts    CertOptions
		wantErr bool
	}{
		{
			name: "Issue root CA",
			opts: CertOptions{
				Type: TypeRootCA,
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				TTLInHours: 8760,
				KeyPair:    mustGenerateKeyPair(t, RSA_2048),
			},
			wantErr: false,
		},
		{
			name: "Issue intermediate CA",
			opts: func() CertOptions {
				// Create root CA first
				rootKeyPair := mustGenerateKeyPair(t, RSA_2048)
				rootOpts := CertOptions{
					Type: TypeRootCA,
					Subject: pkix.Name{
						CommonName: "Test Root CA",
					},
					TTLInHours: 8760,
					KeyPair:    rootKeyPair,
				}
				rootCert, err := IssueCertificate(rootOpts)
				if err != nil {
					t.Fatalf("failed to create root CA: %v", err)
				}
				return CertOptions{
					Type: TypeIntermediate,
					Subject: pkix.Name{
						CommonName: "Test Intermediate CA",
					},
					TTLInHours: 4380,
					KeyPair:    mustGenerateKeyPair(t, RSA_2048),
					ParentCert: rootCert,
					ParentKey:  rootKeyPair.PrivateKey,
				}
			}(),
			wantErr: false,
		},
		{
			name: "Issue leaf certificate",
			opts: func() CertOptions {
				rootKeyPair := mustGenerateKeyPair(t, RSA_2048)
				rootOpts := CertOptions{
					Type: TypeRootCA,
					Subject: pkix.Name{
						CommonName: "Test Root CA",
					},
					TTLInHours: 8760,
					KeyPair:    rootKeyPair,
				}
				rootCert, _ := IssueCertificate(rootOpts)

				// Intermediate
				intKeyPair := mustGenerateKeyPair(t, RSA_2048)
				intOpts := CertOptions{
					Type: TypeIntermediate,
					Subject: pkix.Name{
						CommonName: "Test Intermediate CA",
					},
					TTLInHours: 4380,
					KeyPair:    intKeyPair,
					ParentCert: rootCert,
					ParentKey:  rootKeyPair.PrivateKey,
				}
				intCert, _ := IssueCertificate(intOpts)

				return CertOptions{
					Type: TypeLeaf,
					Subject: pkix.Name{
						CommonName: "test.example.com",
					},
					SANs: SANs{
						DNSNames: []string{"test.example.com", "www.test.example.com"},
					},
					TTLInHours: 8760,
					KeyPair:    mustGenerateKeyPair(t, RSA_2048),
					ParentCert: intCert,
					ParentKey:  intKeyPair.PrivateKey,
				}
			}(),
			wantErr: false,
		},
		{
			name: "Missing key pair",
			opts: CertOptions{
				Type: TypeRootCA,
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := IssueCertificate(tc.opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("IssueCertificate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if cert == nil {
					t.Fatal("certificate is nil")
				}
				// Validate basic cert properties
				if cert.SerialNumber == nil {
					t.Fatal("serial number is nil")
				}
				if cert.NotBefore.After(time.Now()) {
					t.Fatal("not before is in the future")
				}
				if cert.NotAfter.Before(time.Now()) {
					t.Fatal("not after is in the past")
				}
				switch tc.opts.Type {
				case TypeRootCA, TypeIntermediate:
					if !cert.IsCA {
						t.Fatal("expected CA certificate")
					}
				case TypeLeaf:
					if cert.IsCA {
						t.Fatal("expected non-CA certificate")
					}
				}
			}
		})
	}
}

func mustGenerateKeyPair(t *testing.T, keyType KeyType) *KeyPair {
	t.Helper()
	kp, err := GetKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestGetBaseTemplate(t *testing.T) {
	subject := pkix.Name{CommonName: "test"}
	serialNumber, err := utils.GetSerialNumber() // from utils
	if err != nil {
		t.Fatalf("failed to get serial number: %v", err)
	}

	tmpl := GetBaseTemplate(subject, serialNumber, 100, true)

	if tmpl.SerialNumber == nil {
		t.Fatal("serial number is nil")
	}
	if tmpl.Subject.CommonName != "test" {
		t.Fatal("subject common name doesn't match")
	}
	if tmpl.IsCA != true {
		t.Fatal("isCA should be true")
	}
}
