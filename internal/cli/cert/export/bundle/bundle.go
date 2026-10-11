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
	"context"
	"log"

	"github.com/tassok-wasi/pkit/internal/service"
)

type BundleCmd struct {
	ID         int64  `arg:"" help:"Database ID of the leaf certificate to export as a bundle."`
	PassPhrase string `name:"pass-phrase" help:"Passphrase to encrypt the private key (applicable only to PKCS#12 format)."`
	Path       string `name:"path" type:"path" help:"Destination directory or file path for the exported bundle."`
	Format     string `name:"format" short:"f" required:"" enum:"pkcs12,pem" default:"pkcs12" help:"File format for the exported bundle."`
}

func (bc *BundleCmd) Run(ctx context.Context, svc *service.Service) error {
	outPath, err := svc.ExportCertificateBundle(ctx, service.ExportBundleRequest{
		ID:         bc.ID,
		Path:       bc.Path,
		Format:     bc.Format,
		PassPhrase: bc.PassPhrase,
	})
	if err != nil {
		return err
	}

	log.Printf("Success: successfully written %s bundle file to: %s", bc.Format, outPath)
	return nil
}
