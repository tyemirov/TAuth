package authkit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/pkg/oauthvalidator"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrGitHubCredentialMissing requires a new GitHub repository authorization.
var ErrGitHubCredentialMissing = errors.New("github.credential_missing")

// GitHubCredential is a provider credential delivered only to a resource backend.
type GitHubCredential struct {
	GitHubID    string `json:"github_id"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type githubCredentialIdentity struct{ tenant, user string }

type databaseGitHubCredential struct {
	TenantID   string `gorm:"primaryKey"`
	UserID     string `gorm:"primaryKey"`
	Ciphertext []byte `gorm:"not null"`
}

func (databaseGitHubCredential) TableName() string { return "github_credentials" }

// SaveGitHubCredential stores an encrypted credential for one exact identity.
func (store *DatabaseUserStore) SaveGitHubCredential(ctx context.Context, tenantID, userID string, encrypted []byte) error {
	if err := store.db.WithContext(ctx).Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}}, DoUpdates: clause.AssignmentColumns([]string{"ciphertext"})}).Create(&databaseGitHubCredential{TenantID: tenantID, UserID: userID, Ciphertext: encrypted}).Error; err != nil {
		return fmt.Errorf("github.credential_save: %w", err)
	}
	return nil
}

// LoadGitHubCredential retrieves ciphertext for one exact identity.
func (store *DatabaseUserStore) LoadGitHubCredential(ctx context.Context, tenantID, userID string) ([]byte, error) {
	var record databaseGitHubCredential
	err := store.db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrGitHubCredentialMissing
	}
	if err != nil {
		return nil, fmt.Errorf("github.credential_load: %w", err)
	}
	return record.Ciphertext, nil
}

// SaveGitHubCredential stores ciphertext in the in-memory account store.
func (store *MemoryPasswordCredentialStore) SaveGitHubCredential(ctx context.Context, tenantID, userID string, encrypted []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("github.credential_save: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.githubCredentials[githubCredentialIdentity{tenantID, userID}] = slices.Clone(encrypted)
	return nil
}

// LoadGitHubCredential retrieves ciphertext from the in-memory account store.
func (store *MemoryPasswordCredentialStore) LoadGitHubCredential(ctx context.Context, tenantID, userID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("github.credential_load: %w", err)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	encrypted, found := store.githubCredentials[githubCredentialIdentity{tenantID, userID}]
	if !found {
		return nil, ErrGitHubCredentialMissing
	}
	return slices.Clone(encrypted), nil
}

func (sessions *OAuthBrowserSessions) githubCredentialCipher(tenantID string) (cipher.AEAD, error) {
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists || config.GitHubOAuth.CredentialKey() == "" {
		return nil, ErrGitHubCredentialMissing
	}
	block, err := aes.NewCipher([]byte(config.GitHubOAuth.CredentialKey()))
	if err != nil {
		return nil, fmt.Errorf("github.credential_cipher: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func githubCredentialBinding(tenantID, userID string) []byte {
	encoded, _ := json.Marshal([]string{"tauth.github.credential", tenantID, userID})
	return encoded
}

func (sessions *OAuthBrowserSessions) saveGitHubCredential(ctx context.Context, tenantID, userID string, credential GitHubCredential) error {
	box, err := sessions.githubCredentialCipher(tenantID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("github.credential_encode: %w", err)
	}
	return sessions.accountStore.SaveGitHubCredential(ctx, tenantID, userID, box.Seal(nil, nil, encoded, githubCredentialBinding(tenantID, userID)))
}

// GitHubCredential retrieves a credential owned by a linked GitHub identity.
func (sessions *OAuthBrowserSessions) GitHubCredential(ctx context.Context, tenantID, userID string) (GitHubCredential, error) {
	identities, err := sessions.ProviderIdentities(ctx, tenantID, userID, []string{tenants.GitHubProvider})
	if err != nil {
		return GitHubCredential{}, err
	}
	box, err := sessions.githubCredentialCipher(tenantID)
	if err != nil {
		return GitHubCredential{}, err
	}
	encrypted, err := sessions.accountStore.LoadGitHubCredential(ctx, tenantID, userID)
	if err != nil {
		return GitHubCredential{}, err
	}
	encoded, err := box.Open(nil, nil, encrypted, githubCredentialBinding(tenantID, userID))
	if err != nil {
		return GitHubCredential{}, fmt.Errorf("github.credential_decrypt: %w", err)
	}
	var credential GitHubCredential
	if err := json.Unmarshal(encoded, &credential); err != nil {
		return GitHubCredential{}, fmt.Errorf("github.credential_decode: %w", err)
	}
	if !slices.ContainsFunc(identities, func(identity oauthvalidator.ProviderIdentity) bool {
		return identity.Provider == tenants.GitHubProvider && identity.ProviderID == credential.GitHubID
	}) {
		return GitHubCredential{}, ErrGitHubCredentialMissing
	}
	return credential, nil
}
