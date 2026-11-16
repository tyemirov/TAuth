//go:build tauth_testfixture

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"sort"
	"strings"

	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/tenants"
)

// validateJSONShape rejects ambiguous object keys and nulls before typed decoding.
func validateJSONShape(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("fixture input must contain valid JSON")
		}
		if token == nil {
			return errors.New("fixture input must not contain null")
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return errors.New("fixture input has an invalid object")
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return errors.New("fixture input must not contain duplicate object keys")
				}
				keys[name] = true
				if err := value(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
		default:
			return errors.New("fixture input has an invalid container")
		}
		if _, err := decoder.Token(); err != nil {
			return errors.New("fixture input has an unclosed container")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("fixture input must contain one JSON document")
	}
	return nil
}

func addPasswordUsers(request fixtureRequest, application *tenants.FileTenant, emails map[string]bool) error {
	aliases := make([]string, 0, len(request.PasswordUsers))
	for alias := range request.PasswordUsers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		user := request.PasswordUsers[alias]
		if !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(alias) {
			return errors.New("password_users requires lowercase fixture aliases")
		}
		if _, exists := request.Accounts[alias]; exists {
			return errors.New("fixture aliases must be unique across accounts and password_users")
		}
		email := strings.ToLower(user.Email)
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email || strings.TrimSpace(user.Email) != user.Email || !(strings.HasSuffix(email, "@example.com") || strings.HasSuffix(email, ".invalid")) {
			return errors.New("password_users requires synthetic example.com or .invalid email addresses")
		}
		if emails[email] {
			return errors.New("fixture account emails must be unique after normalization")
		}
		emails[email] = true
		if user.DisplayName == "" || strings.TrimSpace(user.DisplayName) != user.DisplayName {
			return errors.New("password_users requires a display_name without outer whitespace")
		}
		hash, err := authkit.HashPassword(user.Password)
		if err != nil {
			return fmt.Errorf("password_users requires a password satisfying the canonical policy: %w", err)
		}
		application.PasswordAuth.Enabled = true
		application.PasswordAuth.Users = append(application.PasswordAuth.Users, tenants.FilePasswordUser{Email: email, DisplayName: user.DisplayName, PasswordHash: hash})
	}
	return nil
}
