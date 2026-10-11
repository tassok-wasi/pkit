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
	"fmt"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ExportCmd struct {
	ID     int64  `arg:"" help:"Database ID of the key pair to export."`
	Path   string `name:"path" short:"p" help:"Destination directory or file path for the exported key pair."`
	Format string `name:"format" short:"f" default:"pem" help:"File format for the exported key pair (e.g., pem, der)."`
	Blob   bool   `name:"blob" short:"b" help:"Export the private key as an encrypted binary blob."`
}

func (ec *ExportCmd) Run(ctx context.Context, svc *service.Service) error {
	privKeyFilePath, pubKeyFilePath, err := svc.ExportKey(ctx, service.ExportKeyRequest{
		ID:     ec.ID,
		Path:   ec.Path,
		Format: ec.Format,
		Blob:   ec.Blob,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Successfully exported Private Key to: %s\n", privKeyFilePath)
	fmt.Printf("Successfully exported Public Key to:  %s\n", pubKeyFilePath)
	return nil
}
