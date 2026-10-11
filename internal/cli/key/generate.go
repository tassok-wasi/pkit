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

package key

import (
	"context"

	"github.com/tassok-wasi/pkit/internal/service"
)

type GenerateCmd struct {
	KeyType string `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Cryptographic algorithm and key size to generate."`
	Name    string `name:"name" required:"" help:"Friendly identifier name for the key pair in the database."`
}

func (gc *GenerateCmd) Run(ctx context.Context, svc *service.Service) error {
	_, err := svc.GenerateKey(ctx, service.GenerateKeyRequest{
		KeyType: gc.KeyType,
		Name:    gc.Name,
	})
	return err
}
