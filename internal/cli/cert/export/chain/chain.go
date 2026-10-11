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

package chain

import (
	"context"
	"log"

	"github.com/tassok-wasi/pkit/internal/service"
)

type ChainCmd struct {
	ID     int64  `arg:"" help:"Database ID of the leaf certificate whose certificate chain to export."`
	Path   string `name:"path" type:"path" help:"Destination directory or file path for the exported chain."`
	Format string `name:"format" short:"f" required:"" enum:"pem,pkcs7" default:"pem" help:"File format for the exported chain."`
}

func (cc *ChainCmd) Run(ctx context.Context, svc *service.Service) error {
	outPath, err := svc.ExportCertificateChain(ctx, service.ExportRequest{
		ID:     cc.ID,
		Path:   cc.Path,
		Format: cc.Format,
	})
	if err != nil {
		return err
	}

	log.Printf("Success: successfully written %s certificate chain to: %s", cc.Format, outPath)

	return nil
}
