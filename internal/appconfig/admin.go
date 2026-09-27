package appconfig

import (
	"fmt"
	"net/mail"
	"sort"
	"strings"
)

// AdminSettings grants account-directory access to verified console emails.
type AdminSettings struct {
	Emails []string `yaml:"emails"`
}

func normalizeAdmin(settings AdminSettings) (AdminSettings, error) {
	seen := make(map[string]bool)
	result := AdminSettings{Emails: []string{}}
	for _, raw := range settings.Emails {
		email := strings.ToLower(strings.TrimSpace(raw))
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			return AdminSettings{}, fmt.Errorf("%s: admin.emails requires email addresses", ErrorCodeInvalidConfigFile)
		}
		if !seen[email] {
			result.Emails = append(result.Emails, email)
			seen[email] = true
		}
	}
	sort.Strings(result.Emails)
	return result, nil
}
