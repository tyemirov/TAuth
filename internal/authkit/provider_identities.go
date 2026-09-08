package authkit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tyemirov/tauth/internal/tenants"
	"github.com/tyemirov/tauth/pkg/oauthvalidator"
)

// AccountIdentity is an immutable provider binding in the account store.
type AccountIdentity struct {
	Provider   string
	ProviderID string
}

// AccountIdentities returns the current provider bindings for one active account.
func (store *MemoryPasswordCredentialStore) AccountIdentities(ctx context.Context, tenantID, accountID string) ([]AccountIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("account.identities: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return nil, ErrAccountNotFound
	}
	if account.state != accountStateActive {
		return nil, ErrAccountNotActive
	}
	identities := make([]AccountIdentity, 0)
	for _, identity := range store.identities[tenantID] {
		if identity.accountID == accountID {
			identities = append(identities, AccountIdentity{identity.provider, identity.providerID})
		}
	}
	return identities, nil
}

// AccountIdentities returns the current provider bindings for one active account.
func (store *DatabaseUserStore) AccountIdentities(ctx context.Context, tenantID, accountID string) ([]AccountIdentity, error) {
	profile, err := store.ResolveAccountProfile(ctx, tenantID, accountID)
	if err != nil {
		return nil, err
	}
	if profile.State != accountStateActive {
		return nil, ErrAccountNotActive
	}
	var records []databaseAccountIdentityRecord
	if err := store.db.WithContext(ctx).Where("tenant_id = ? AND account_id = ?", tenantID, accountID).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("account.identities: %w", err)
	}
	identities := make([]AccountIdentity, 0, len(records))
	for _, record := range records {
		identities = append(identities, AccountIdentity{record.Provider, record.ProviderID})
	}
	return identities, nil
}

// ErrRequiredIdentityMissing means the subject cannot prove a required provider identity.
var ErrRequiredIdentityMissing = errors.New("oauth.required_identity_missing")

// ProviderIdentities resolves disclosure only from current tenant identity records.
func (sessions *OAuthBrowserSessions) ProviderIdentities(ctx context.Context, tenantID, userID string, required []string) (oauthvalidator.ProviderIdentities, error) {
	if len(required) == 0 {
		return nil, nil
	}
	config, exists := sessions.registry.ConfigByID(tenantID)
	if !exists || !config.GitHubOAuth.Enabled() {
		return nil, ErrRequiredIdentityMissing
	}
	email, _, _, _, profileErr := sessions.users.GetUserProfile(ctx, tenantID, userID)
	if profileErr != nil {
		return nil, fmt.Errorf("oauth.identity.profile: %w", profileErr)
	}
	if !isAllowedUser(email, config.AllowedUsers) {
		return nil, ErrRequiredIdentityMissing
	}
	var identities []AccountIdentity
	if config.AccountManagementEnabled {
		if sessions.accountStore == nil {
			return nil, fmt.Errorf("oauth.identity.account_store_missing")
		}
		var err error
		identities, err = sessions.accountStore.AccountIdentities(ctx, tenantID, userID)
		if errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrAccountNotActive) {
			return nil, ErrRequiredIdentityMissing
		}
		if err != nil {
			return nil, fmt.Errorf("oauth.identity.lookup: %w", err)
		}
	} else {
		provider, providerID, found := strings.Cut(userID, ":")
		if !found || provider != tenants.GitHubProvider {
			return nil, ErrRequiredIdentityMissing
		}
		identities = []AccountIdentity{{provider, providerID}}
	}
	result := make(oauthvalidator.ProviderIdentities, 0)
	for _, provider := range required {
		found := false
		for _, identity := range identities {
			if identity.Provider != provider {
				continue
			}
			record, err := oauthvalidator.NewProviderIdentity(identity.Provider, identity.ProviderID)
			if err != nil {
				return nil, fmt.Errorf("oauth.identity.record: %w", err)
			}
			result = append(result, record)
			found = true
		}
		if !found {
			return nil, ErrRequiredIdentityMissing
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ProviderID < result[right].ProviderID })
	return result, nil
}
