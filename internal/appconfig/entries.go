package appconfig

import "strings"

// ExpandCommaSeparatedEntries splits comma-delimited values and trims whitespace.
func ExpandCommaSeparatedEntries(entries []string) []string {
	expanded := make([]string, 0, len(entries))
	for _, entry := range entries {
		for _, chunk := range strings.Split(entry, ",") {
			value := strings.TrimSpace(chunk)
			if value != "" {
				expanded = append(expanded, value)
			}
		}
	}
	return expanded
}
