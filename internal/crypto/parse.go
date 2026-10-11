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

package crypto

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SplitCSV splits a comma-separated string into trimmed, non-empty segments.
func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}

// SanitizeFilename safely truncates path operators and filters malicious special characters.
func SanitizeFilename(input string, fallback string) string {
	cleaned := strings.ReplaceAll(input, "..", "")
	cleaned = strings.ReplaceAll(cleaned, "/", "")
	cleaned = strings.ReplaceAll(cleaned, "\\", "")

	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-\. ]+`)
	cleaned = reg.ReplaceAllString(cleaned, "")

	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return fallback
	}

	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}

	return cleaned
}

var durationRegex = regexp.MustCompile(`^(\d+)([hdy])$`)

// ParseTTLToHours parses duration strings like "1000h", "30d", "10y" into total hours.
func ParseTTLToHours(ttlStr string) (int, error) {
	matches := durationRegex.FindStringSubmatch(ttlStr)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration format %q: must be a number followed by 'h', 'd', or 'y' (e.g., 1000h, 30d, 10y)", ttlStr)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration: %v", err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("duration must be greater than zero")
	}

	unit := matches[2]
	switch unit {
	case "h":
		return value, nil
	case "d":
		return value * 24, nil
	case "y":
		// Approximating a year as 365 days (8760 hours)
		return value * 24 * 365, nil
	default:
		return 0, fmt.Errorf("unsupported time unit: %s", unit)
	}
}
