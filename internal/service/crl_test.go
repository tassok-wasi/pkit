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

package service

import (
	"testing"
	"time"
)

func TestFormatCRLName(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 4, 53, 57, 0, time.UTC)

	tests := []struct {
		name       string
		commonName string
		want       string
	}{
		{
			name:       "replaces spaces with underscores",
			commonName: "My Test Root CA",
			want:       "My_Test_Root_CA_20260720_045357",
		},
		{
			name:       "handles single word common name",
			commonName: "RootCA",
			want:       "RootCA_20260720_045357",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatCRLName(tt.commonName, now)
			if got != tt.want {
				t.Errorf("formatCRLName() = %v, want %v", got, tt.want)
			}
		})
	}
}
