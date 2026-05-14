package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	passwordUserIDPrefix         = "email:"
	passwordBcryptCost           = bcrypt.DefaultCost
	passwordMaxBytes             = 72
	passwordCredentialTimingHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhiG6MQT2Vjex6Dh2M1ngqRh5JalXH1V6"
)

var (
	ErrPasswordCredentialInvalid = errors.New("password_auth.invalid_credentials")
	ErrPasswordCredentialConfig  = errors.New("password_auth.invalid_config")
)

// PasswordCredentialSeed describes one configured password credential.
type PasswordCredentialSeed struct {
	UserEmail    string
	DisplayName  string
	AvatarURL    string
	PasswordHash string
}

// PasswordCredentialProfile is the trusted profile returned after password verification.
type PasswordCredentialProfile struct {
	UserEmail   string
	DisplayName string
	AvatarURL   string
}

type passwordCredential struct {
	userEmail    string
	displayName  string
	avatarURL    string
	passwordHash string
}

type passwordHashComparer func(hashedPassword []byte, password []byte) error

// MemoryPasswordCredentialStore stores password credentials in memory.
type MemoryPasswordCredentialStore struct {
	mu                   sync.RWMutex
	tenants              map[string]map[string]passwordCredential
	passwordHashComparer passwordHashComparer
}

// NewMemoryPasswordCredentialStore constructs an empty in-memory credential store.
func NewMemoryPasswordCredentialStore() *MemoryPasswordCredentialStore {
	return &MemoryPasswordCredentialStore{
		tenants:              make(map[string]map[string]passwordCredential),
		passwordHashComparer: bcrypt.CompareHashAndPassword,
	}
}

// HashPassword returns a bcrypt hash suitable for password credential seeding.
func HashPassword(password string) (string, error) {
	if err := validatePlainPassword(password); err != nil {
		return "", err
	}
	hashBytes, hashErr := bcrypt.GenerateFromPassword([]byte(password), passwordBcryptCost)
	if hashErr != nil {
		return "", fmt.Errorf("password_auth.hash: %w", hashErr)
	}
	return string(hashBytes), nil
}

// UpsertPasswordCredential inserts or replaces one password credential.
func (store *MemoryPasswordCredentialStore) UpsertPasswordCredential(ctx context.Context, tenantID string, credential PasswordCredentialSeed) error {
	normalizedCredential, normalizeErr := normalizePasswordCredentialSeed(credential)
	if normalizeErr != nil {
		return normalizeErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.tenants[tenantID]; !exists {
		store.tenants[tenantID] = make(map[string]passwordCredential)
	}
	store.tenants[tenantID][normalizedCredential.userEmail] = normalizedCredential
	return nil
}

// ReconcilePasswordCredentials removes tenant credentials absent from the current config.
func (store *MemoryPasswordCredentialStore) ReconcilePasswordCredentials(ctx context.Context, tenantID string, configuredEmails []string) error {
	configuredEmailSet, normalizeErr := normalizePasswordEmailSet(configuredEmails)
	if normalizeErr != nil {
		return normalizeErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantCredentials := store.tenants[tenantID]
	for credentialEmail := range tenantCredentials {
		if _, exists := configuredEmailSet[credentialEmail]; !exists {
			delete(tenantCredentials, credentialEmail)
		}
	}
	if len(tenantCredentials) == 0 {
		delete(store.tenants, tenantID)
	}
	return nil
}

// AuthenticatePassword verifies a password credential and returns its profile.
func (store *MemoryPasswordCredentialStore) AuthenticatePassword(ctx context.Context, tenantID string, userEmail string, password string) (PasswordCredentialProfile, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	if err := validatePlainPassword(password); err != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	store.mu.RLock()
	tenantCredentials := store.tenants[tenantID]
	credential, exists := tenantCredentials[normalizedEmail]
	store.mu.RUnlock()
	if !exists {
		_ = store.passwordHashComparer([]byte(passwordCredentialTimingHash), []byte(password))
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	if compareErr := store.passwordHashComparer([]byte(credential.passwordHash), []byte(password)); compareErr != nil {
		return PasswordCredentialProfile{}, ErrPasswordCredentialInvalid
	}
	return PasswordCredentialProfile{
		UserEmail:   credential.userEmail,
		DisplayName: credential.displayName,
		AvatarURL:   credential.avatarURL,
	}, nil
}

func normalizePasswordCredentialSeed(credential PasswordCredentialSeed) (passwordCredential, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(credential.UserEmail)
	if emailErr != nil {
		return passwordCredential{}, fmt.Errorf("%w: email", ErrPasswordCredentialConfig)
	}
	passwordHash := strings.TrimSpace(credential.PasswordHash)
	if passwordHash == "" {
		return passwordCredential{}, fmt.Errorf("%w: password_hash", ErrPasswordCredentialConfig)
	}
	if _, hashErr := bcrypt.Cost([]byte(passwordHash)); hashErr != nil {
		return passwordCredential{}, fmt.Errorf("%w: password_hash", ErrPasswordCredentialConfig)
	}
	displayName := strings.TrimSpace(credential.DisplayName)
	if displayName == "" {
		displayName = normalizedEmail
	}
	return passwordCredential{
		userEmail:    normalizedEmail,
		displayName:  displayName,
		avatarURL:    strings.TrimSpace(credential.AvatarURL),
		passwordHash: passwordHash,
	}, nil
}

func normalizePasswordEmail(rawEmail string) (string, error) {
	trimmedEmail := strings.TrimSpace(rawEmail)
	if trimmedEmail == "" {
		return "", fmt.Errorf("password_auth.email_missing")
	}
	normalizedEmail := strings.ToLower(trimmedEmail)
	parsedAddress, parseErr := mail.ParseAddress(normalizedEmail)
	if parseErr != nil {
		return "", parseErr
	}
	if parsedAddress.Address != normalizedEmail {
		return "", fmt.Errorf("password_auth.email_invalid")
	}
	return normalizedEmail, nil
}

func normalizePasswordEmailSet(rawEmails []string) (map[string]struct{}, error) {
	emailSet := make(map[string]struct{}, len(rawEmails))
	for _, rawEmail := range rawEmails {
		normalizedEmail, emailErr := normalizePasswordEmail(rawEmail)
		if emailErr != nil {
			return nil, fmt.Errorf("%w: email", ErrPasswordCredentialConfig)
		}
		emailSet[normalizedEmail] = struct{}{}
	}
	return emailSet, nil
}

func validatePlainPassword(password string) error {
	if password == "" {
		return fmt.Errorf("%w: password", ErrPasswordCredentialConfig)
	}
	if len([]byte(password)) > passwordMaxBytes {
		return fmt.Errorf("%w: password_too_long", ErrPasswordCredentialConfig)
	}
	return nil
}
