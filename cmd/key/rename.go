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
	"strings"

	"pkit/db/base"
)

type RenameCmd struct {
	ID   int64  `arg:"" help:"Database ID of the key pair to rename."`
	Name string `name:"name" short:"n" required:"" help:"New friendly name for the key pair."`
}

func (rc *RenameCmd) Run(ctx context.Context, query base.Querier) error {
	newName := strings.TrimSpace(rc.Name)
	if newName == "" {
		return fmt.Errorf("new key name cannot be empty")
	}

	_, err := query.GetKeyByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch key from DB: %w", err)
	}

	_, err = query.UpdateKeyName(ctx, base.UpdateKeyNameParams{
		ID:   rc.ID,
		Name: newName,
	})
	if err != nil {
		return fmt.Errorf("failed to rename key in DB: %w", err)
	}

	fmt.Printf("Successfully renamed key %d to: %s\n", rc.ID, newName)
	return nil
}
