package authkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	accountStatePendingVerification   = "pending_verification"
	accountStateActive                = "active"
	accountStateDisabled              = "disabled"
	accountProviderPassword           = "password"
	accountProviderGoogle             = "google"
	accountProviderApple              = "apple"
	accountChallengeEmailVerification = "email_verification"
	accountChallengePasswordReset     = "password_reset"
	accountChallengePasswordLink      = "password_link"
)

var (
	ErrAccountExists           = errors.New("account.exists")
	ErrAccountNotFound         = errors.New("account.not_found")
	ErrAccountNotActive        = errors.New("account.not_active")
	ErrAccountDisabled         = errors.New("account.disabled")
	ErrAccountChallengeInvalid = errors.New("account.challenge_invalid")
	ErrAccountLastIdentity     = errors.New("account.last_identity")
)

// AccountPasswordRequest carries a first-party password account request.
type AccountPasswordRequest struct {
	UserEmail   string
	DisplayName string
	AvatarURL   string
	Password    string
}

// AccountChallenge is the delivery payload for one-time account challenges.
type AccountChallenge struct {
	AccountID   string
	Token       string
	ExpiresUnix int64
}

// AccountProfile is the trusted account profile used for session finalization.
type AccountProfile struct {
	AccountID   string
	UserEmail   string
	DisplayName string
	AvatarURL   string
	Roles       []string
	State       string
}

// GoogleAccountIdentity describes a verified Google identity.
type GoogleAccountIdentity struct {
	Subject     string
	UserEmail   string
	DisplayName string
	AvatarURL   string
}

// AccountProviderIdentity describes a verified external provider identity.
type AccountProviderIdentity struct {
	Provider    string
	Subject     string
	UserEmail   string
	DisplayName string
	AvatarURL   string
}

type accountRecord struct {
	accountID   string
	userEmail   string
	displayName string
	avatarURL   string
	state       string
	roles       []string
}

type accountIdentityRecord struct {
	accountID  string
	provider   string
	providerID string
}

type accountChallengeRecord struct {
	accountID    string
	kind         string
	tokenHash    string
	userEmail    string
	displayName  string
	avatarURL    string
	passwordHash string
	expiresUnix  int64
	consumed     bool
}

func (store *MemoryPasswordCredentialStore) ensureAccountMaps(tenantID string) {
	if _, exists := store.tenants[tenantID]; !exists {
		store.tenants[tenantID] = make(map[string]passwordCredential)
	}
	if store.accounts == nil {
		store.accounts = make(map[string]map[string]*accountRecord)
	}
	if _, exists := store.accounts[tenantID]; !exists {
		store.accounts[tenantID] = make(map[string]*accountRecord)
	}
	if store.identities == nil {
		store.identities = make(map[string]map[string]accountIdentityRecord)
	}
	if _, exists := store.identities[tenantID]; !exists {
		store.identities[tenantID] = make(map[string]accountIdentityRecord)
	}
	if store.challenges == nil {
		store.challenges = make(map[string]map[string]*accountChallengeRecord)
	}
	if _, exists := store.challenges[tenantID]; !exists {
		store.challenges[tenantID] = make(map[string]*accountChallengeRecord)
	}
}

// CreatePasswordSignup starts a tenant-managed password signup.
func (store *MemoryPasswordCredentialStore) CreatePasswordSignup(ctx context.Context, tenantID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error) {
	credential, credentialErr := buildAccountPasswordCredential(request)
	if credentialErr != nil {
		return AccountChallenge{}, credentialErr
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("account.signup.token: %w", tokenErr)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	if _, exists := store.tenants[tenantID][credential.userEmail]; exists {
		return AccountChallenge{}, ErrAccountExists
	}
	if _, exists := store.identities[tenantID][identityKey(accountProviderPassword, credential.userEmail)]; exists {
		return AccountChallenge{}, ErrAccountExists
	}
	accountID, accountIDErr := store.newOpaqueAccountIDLocked(tenantID)
	if accountIDErr != nil {
		return AccountChallenge{}, accountIDErr
	}
	store.accounts[tenantID][accountID] = &accountRecord{
		accountID:   accountID,
		userEmail:   credential.userEmail,
		displayName: credential.displayName,
		avatarURL:   credential.avatarURL,
		state:       accountStatePendingVerification,
		roles:       []string{defaultUserRole},
	}
	store.tenants[tenantID][credential.userEmail] = passwordCredential{
		accountID:    accountID,
		userEmail:    credential.userEmail,
		displayName:  credential.displayName,
		avatarURL:    credential.avatarURL,
		passwordHash: credential.passwordHash,
		verified:     false,
	}
	store.challenges[tenantID][tokenHash] = &accountChallengeRecord{
		accountID:    accountID,
		kind:         accountChallengeEmailVerification,
		tokenHash:    tokenHash,
		userEmail:    credential.userEmail,
		displayName:  credential.displayName,
		avatarURL:    credential.avatarURL,
		passwordHash: credential.passwordHash,
		expiresUnix:  expiresUnix,
	}
	return AccountChallenge{AccountID: accountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// CancelPasswordSignup removes a pending signup after delivery fails.
func (store *MemoryPasswordCredentialStore) CancelPasswordSignup(_ context.Context, tenantID string, accountID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	account, exists := store.accounts[tenantID][accountID]
	if !exists || account.state != accountStatePendingVerification {
		return fmt.Errorf("account.signup_cancel.invalid_state")
	}
	delete(store.accounts[tenantID], accountID)
	for userEmail, credential := range store.tenants[tenantID] {
		if credential.accountID == accountID {
			delete(store.tenants[tenantID], userEmail)
		}
	}
	for tokenHash, challenge := range store.challenges[tenantID] {
		if challenge.accountID == accountID && challenge.kind == accountChallengeEmailVerification {
			delete(store.challenges[tenantID], tokenHash)
		}
	}
	return nil
}

// VerifyEmailChallenge activates a pending signup.
func (store *MemoryPasswordCredentialStore) VerifyEmailChallenge(ctx context.Context, tenantID string, token string) (AccountProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, challengeErr := store.consumeChallengeLocked(tenantID, token, accountChallengeEmailVerification)
	if challengeErr != nil {
		return AccountProfile{}, challengeErr
	}
	account := store.accounts[tenantID][challenge.accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	account.state = accountStateActive
	store.identities[tenantID][identityKey(accountProviderPassword, challenge.userEmail)] = accountIdentityRecord{
		accountID:  challenge.accountID,
		provider:   accountProviderPassword,
		providerID: challenge.userEmail,
	}
	credential := store.tenants[tenantID][challenge.userEmail]
	credential.verified = true
	credential.accountID = challenge.accountID
	store.tenants[tenantID][challenge.userEmail] = credential
	return profileFromAccount(account), nil
}

// StartPasswordReset issues a reset challenge for an existing password identity.
func (store *MemoryPasswordCredentialStore) StartPasswordReset(ctx context.Context, tenantID string, userEmail string, expiresUnix int64) (AccountChallenge, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return AccountChallenge{}, ErrPasswordCredentialInvalid
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("account.reset.token: %w", tokenErr)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	credential, exists := store.tenants[tenantID][normalizedEmail]
	if !exists || credential.accountID == "" || !credential.verified {
		return AccountChallenge{}, ErrAccountNotFound
	}
	account := store.accounts[tenantID][credential.accountID]
	if account == nil {
		return AccountChallenge{}, ErrAccountNotFound
	}
	store.challenges[tenantID][tokenHash] = &accountChallengeRecord{
		accountID:   account.accountID,
		kind:        accountChallengePasswordReset,
		tokenHash:   tokenHash,
		userEmail:   credential.userEmail,
		displayName: credential.displayName,
		avatarURL:   credential.avatarURL,
		expiresUnix: expiresUnix,
	}
	return AccountChallenge{AccountID: account.accountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// CompletePasswordReset rotates the credential for a valid reset challenge.
func (store *MemoryPasswordCredentialStore) CompletePasswordReset(ctx context.Context, tenantID string, token string, password string) (AccountProfile, error) {
	passwordHash, hashErr := HashPassword(password)
	if hashErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, challengeErr := store.consumeChallengeLocked(tenantID, token, accountChallengePasswordReset)
	if challengeErr != nil {
		return AccountProfile{}, challengeErr
	}
	account := store.accounts[tenantID][challenge.accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	if account.state == accountStateDisabled {
		return AccountProfile{}, ErrAccountDisabled
	}
	credential := store.tenants[tenantID][challenge.userEmail]
	credential.passwordHash = passwordHash
	credential.verified = true
	credential.accountID = account.accountID
	store.tenants[tenantID][challenge.userEmail] = credential
	return profileFromAccount(account), nil
}

// ChangePassword rotates a password credential for the authenticated account.
func (store *MemoryPasswordCredentialStore) ChangePassword(ctx context.Context, tenantID string, accountID string, currentPassword string, newPassword string) (AccountProfile, error) {
	newHash, hashErr := HashPassword(newPassword)
	if hashErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	if account.state == accountStateDisabled {
		return AccountProfile{}, ErrAccountDisabled
	}
	if account.state != accountStateActive {
		return AccountProfile{}, ErrAccountNotActive
	}
	passwordIdentity := store.passwordIdentityForAccountLocked(tenantID, accountID)
	if passwordIdentity.providerID == "" {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	credential := store.tenants[tenantID][passwordIdentity.providerID]
	if compareErr := store.passwordHashComparer([]byte(credential.passwordHash), []byte(currentPassword)); compareErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	credential.passwordHash = newHash
	store.tenants[tenantID][passwordIdentity.providerID] = credential
	return profileFromAccount(account), nil
}

// EnsurePasswordAccount links a verified seeded password credential to an account.
func (store *MemoryPasswordCredentialStore) EnsurePasswordAccount(ctx context.Context, tenantID string, userEmail string) (AccountProfile, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(userEmail)
	if emailErr != nil {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	credential, exists := store.tenants[tenantID][normalizedEmail]
	if !exists || !credential.verified {
		return AccountProfile{}, ErrPasswordCredentialInvalid
	}
	accountID := credential.accountID
	if accountID == "" {
		generatedAccountID, accountIDErr := store.newOpaqueAccountIDLocked(tenantID)
		if accountIDErr != nil {
			return AccountProfile{}, accountIDErr
		}
		accountID = generatedAccountID
	} else if validateErr := validateOpaqueAccountID(accountID); validateErr != nil {
		return AccountProfile{}, validateErr
	}
	account := store.accounts[tenantID][accountID]
	if account == nil {
		account = &accountRecord{
			accountID:   accountID,
			userEmail:   credential.userEmail,
			displayName: credential.displayName,
			avatarURL:   credential.avatarURL,
			state:       accountStateActive,
			roles:       []string{defaultUserRole},
		}
		store.accounts[tenantID][accountID] = account
	} else if account.state == accountStateDisabled {
		return AccountProfile{}, ErrAccountDisabled
	} else if account.state != accountStateActive {
		return AccountProfile{}, ErrAccountNotActive
	}
	store.identities[tenantID][identityKey(accountProviderPassword, normalizedEmail)] = accountIdentityRecord{
		accountID:  accountID,
		provider:   accountProviderPassword,
		providerID: normalizedEmail,
	}
	credential.accountID = accountID
	store.tenants[tenantID][normalizedEmail] = credential
	return profileFromAccount(account), nil
}

// CreatePasswordLink starts linking a password identity to an existing account.
func (store *MemoryPasswordCredentialStore) CreatePasswordLink(ctx context.Context, tenantID string, accountID string, request AccountPasswordRequest, expiresUnix int64) (AccountChallenge, error) {
	credential, credentialErr := buildAccountPasswordCredential(request)
	if credentialErr != nil {
		return AccountChallenge{}, credentialErr
	}
	token, tokenHash, tokenErr := generateRefreshOpaque()
	if tokenErr != nil {
		return AccountChallenge{}, fmt.Errorf("account.link_password.token: %w", tokenErr)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountChallenge{}, ErrAccountNotFound
	}
	if _, exists := store.identities[tenantID][identityKey(accountProviderPassword, credential.userEmail)]; exists {
		return AccountChallenge{}, ErrAccountExists
	}
	store.challenges[tenantID][tokenHash] = &accountChallengeRecord{
		accountID:    accountID,
		kind:         accountChallengePasswordLink,
		tokenHash:    tokenHash,
		userEmail:    credential.userEmail,
		displayName:  credential.displayName,
		avatarURL:    credential.avatarURL,
		passwordHash: credential.passwordHash,
		expiresUnix:  expiresUnix,
	}
	return AccountChallenge{AccountID: accountID, Token: token, ExpiresUnix: expiresUnix}, nil
}

// VerifyPasswordLink completes linking a password identity to the authenticated account.
func (store *MemoryPasswordCredentialStore) VerifyPasswordLink(ctx context.Context, tenantID string, accountID string, token string) (AccountProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, challengeErr := store.consumeChallengeLocked(tenantID, token, accountChallengePasswordLink)
	if challengeErr != nil {
		return AccountProfile{}, challengeErr
	}
	if challenge.accountID != accountID {
		return AccountProfile{}, ErrAccountChallengeInvalid
	}
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	store.identities[tenantID][identityKey(accountProviderPassword, challenge.userEmail)] = accountIdentityRecord{
		accountID:  accountID,
		provider:   accountProviderPassword,
		providerID: challenge.userEmail,
	}
	store.tenants[tenantID][challenge.userEmail] = passwordCredential{
		accountID:    accountID,
		userEmail:    challenge.userEmail,
		displayName:  challenge.displayName,
		avatarURL:    challenge.avatarURL,
		passwordHash: challenge.passwordHash,
		verified:     true,
	}
	return profileFromAccount(account), nil
}

// AuthenticateGoogleAccount resolves an existing linked Google identity.
func (store *MemoryPasswordCredentialStore) AuthenticateGoogleAccount(ctx context.Context, tenantID string, identity GoogleAccountIdentity) (AccountProfile, bool, error) {
	return store.AuthenticateProviderAccount(ctx, tenantID, googleProviderIdentity(identity))
}

// AuthenticateProviderAccount resolves an existing linked external provider identity.
func (store *MemoryPasswordCredentialStore) AuthenticateProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, bool, error) {
	normalizedIdentity, identityErr := normalizeAccountProviderIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, false, identityErr
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	linkedIdentity, exists := store.identities[tenantID][identityKey(normalizedIdentity.Provider, normalizedIdentity.Subject)]
	if !exists {
		return AccountProfile{}, false, nil
	}
	account := store.accounts[tenantID][linkedIdentity.accountID]
	if account == nil {
		return AccountProfile{}, false, ErrAccountNotFound
	}
	if account.state == accountStateDisabled {
		return AccountProfile{}, false, ErrAccountDisabled
	}
	if account.state != accountStateActive {
		return AccountProfile{}, false, ErrAccountNotActive
	}
	return profileFromAccount(account), true, nil
}

// UpsertGoogleAccount creates or updates an account for a verified Google identity.
func (store *MemoryPasswordCredentialStore) UpsertGoogleAccount(ctx context.Context, tenantID string, identity GoogleAccountIdentity) (AccountProfile, error) {
	return store.UpsertProviderAccount(ctx, tenantID, googleProviderIdentity(identity))
}

// UpsertProviderAccount creates or updates an account for a verified external provider identity.
func (store *MemoryPasswordCredentialStore) UpsertProviderAccount(ctx context.Context, tenantID string, identity AccountProviderIdentity) (AccountProfile, error) {
	normalizedIdentity, identityErr := normalizeAccountProviderIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, identityErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	identityKeyValue := identityKey(normalizedIdentity.Provider, normalizedIdentity.Subject)
	if linkedIdentity, exists := store.identities[tenantID][identityKeyValue]; exists {
		account := store.accounts[tenantID][linkedIdentity.accountID]
		if account == nil {
			return AccountProfile{}, ErrAccountNotFound
		}
		account.userEmail = normalizedIdentity.UserEmail
		account.displayName = defaultDisplayName(normalizedIdentity.DisplayName, normalizedIdentity.UserEmail)
		account.avatarURL = strings.TrimSpace(normalizedIdentity.AvatarURL)
		return profileFromAccount(account), nil
	}
	accountID, accountIDErr := store.newOpaqueAccountIDLocked(tenantID)
	if accountIDErr != nil {
		return AccountProfile{}, accountIDErr
	}
	account := &accountRecord{
		accountID:   accountID,
		userEmail:   normalizedIdentity.UserEmail,
		displayName: defaultDisplayName(normalizedIdentity.DisplayName, normalizedIdentity.UserEmail),
		avatarURL:   strings.TrimSpace(normalizedIdentity.AvatarURL),
		state:       accountStateActive,
		roles:       []string{defaultUserRole},
	}
	store.accounts[tenantID][accountID] = account
	store.identities[tenantID][identityKeyValue] = accountIdentityRecord{
		accountID:  accountID,
		provider:   normalizedIdentity.Provider,
		providerID: normalizedIdentity.Subject,
	}
	return profileFromAccount(account), nil
}

// LinkGoogleIdentity links a verified Google identity to an existing account.
func (store *MemoryPasswordCredentialStore) LinkGoogleIdentity(ctx context.Context, tenantID string, accountID string, identity GoogleAccountIdentity) (AccountProfile, error) {
	return store.LinkProviderIdentity(ctx, tenantID, accountID, googleProviderIdentity(identity))
}

// LinkProviderIdentity links a verified external provider identity to an existing account.
func (store *MemoryPasswordCredentialStore) LinkProviderIdentity(ctx context.Context, tenantID string, accountID string, identity AccountProviderIdentity) (AccountProfile, error) {
	normalizedIdentity, identityErr := normalizeAccountProviderIdentity(identity)
	if identityErr != nil {
		return AccountProfile{}, identityErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureAccountMaps(tenantID)
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	key := identityKey(normalizedIdentity.Provider, normalizedIdentity.Subject)
	if existingIdentity, exists := store.identities[tenantID][key]; exists && existingIdentity.accountID != accountID {
		return AccountProfile{}, ErrAccountExists
	}
	store.identities[tenantID][key] = accountIdentityRecord{
		accountID:  accountID,
		provider:   normalizedIdentity.Provider,
		providerID: normalizedIdentity.Subject,
	}
	return profileFromAccount(account), nil
}

// UnlinkIdentity removes one linked identity from an account.
func (store *MemoryPasswordCredentialStore) UnlinkIdentity(ctx context.Context, tenantID string, accountID string, provider string, providerID string) (AccountProfile, error) {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	normalizedProviderID := strings.TrimSpace(providerID)
	if normalizedProvider == accountProviderPassword {
		normalizedEmail, emailErr := normalizePasswordEmail(providerID)
		if emailErr != nil {
			return AccountProfile{}, ErrPasswordCredentialInvalid
		}
		normalizedProviderID = normalizedEmail
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	if store.identityCountForAccountLocked(tenantID, accountID) <= 1 {
		return AccountProfile{}, ErrAccountLastIdentity
	}
	key := identityKey(normalizedProvider, normalizedProviderID)
	linkedIdentity, exists := store.identities[tenantID][key]
	if !exists || linkedIdentity.accountID != accountID {
		return AccountProfile{}, ErrAccountNotFound
	}
	delete(store.identities[tenantID], key)
	if normalizedProvider == accountProviderPassword {
		delete(store.tenants[tenantID], normalizedProviderID)
	}
	return profileFromAccount(account), nil
}

// DisableAccount marks an account disabled.
func (store *MemoryPasswordCredentialStore) DisableAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	account.state = accountStateDisabled
	return profileFromAccount(account), nil
}

// ReactivateAccount marks an account active.
func (store *MemoryPasswordCredentialStore) ReactivateAccount(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	account.state = accountStateActive
	return profileFromAccount(account), nil
}

// ResolveAccountProfile returns an account profile by account ID.
func (store *MemoryPasswordCredentialStore) ResolveAccountProfile(ctx context.Context, tenantID string, accountID string) (AccountProfile, error) {
	if validateErr := validateOpaqueAccountID(accountID); validateErr != nil {
		return AccountProfile{}, validateErr
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	return profileFromAccount(account), nil
}

func (store *MemoryPasswordCredentialStore) consumeChallengeLocked(tenantID string, token string, kind string) (*accountChallengeRecord, error) {
	store.ensureAccountMaps(tenantID)
	tokenHash := hashOpaque(strings.TrimSpace(token))
	challenge := store.challenges[tenantID][tokenHash]
	if challenge == nil || challenge.consumed || challenge.kind != kind {
		return nil, ErrAccountChallengeInvalid
	}
	if time.Unix(challenge.expiresUnix, 0).Before(time.Now().UTC()) {
		return nil, ErrAccountChallengeInvalid
	}
	challenge.consumed = true
	return challenge, nil
}

func (store *MemoryPasswordCredentialStore) passwordIdentityForAccountLocked(tenantID string, accountID string) accountIdentityRecord {
	for _, identity := range store.identities[tenantID] {
		if identity.accountID == accountID && identity.provider == accountProviderPassword {
			return identity
		}
	}
	return accountIdentityRecord{}
}

func (store *MemoryPasswordCredentialStore) identityCountForAccountLocked(tenantID string, accountID string) int {
	count := 0
	for _, identity := range store.identities[tenantID] {
		if identity.accountID == accountID {
			count++
		}
	}
	return count
}

func (store *MemoryPasswordCredentialStore) newOpaqueAccountIDLocked(tenantID string) (string, error) {
	for attempt := 0; attempt < accountIDGenerationAttempts; attempt++ {
		accountID, accountIDErr := newOpaqueAccountID()
		if accountIDErr != nil {
			return "", accountIDErr
		}
		if _, exists := store.accounts[tenantID][accountID]; !exists {
			return accountID, nil
		}
	}
	return "", fmt.Errorf("%w: collision", ErrAccountInvalidID)
}

func buildAccountPasswordCredential(request AccountPasswordRequest) (passwordCredential, error) {
	normalizedEmail, emailErr := normalizePasswordEmail(request.UserEmail)
	if emailErr != nil {
		return passwordCredential{}, ErrPasswordCredentialInvalid
	}
	passwordHash, hashErr := HashPassword(request.Password)
	if hashErr != nil {
		return passwordCredential{}, ErrPasswordCredentialInvalid
	}
	return passwordCredential{
		userEmail:    normalizedEmail,
		displayName:  defaultDisplayName(request.DisplayName, normalizedEmail),
		avatarURL:    strings.TrimSpace(request.AvatarURL),
		passwordHash: passwordHash,
	}, nil
}

func googleProviderIdentity(identity GoogleAccountIdentity) AccountProviderIdentity {
	return AccountProviderIdentity{
		Provider:    accountProviderGoogle,
		Subject:     identity.Subject,
		UserEmail:   identity.UserEmail,
		DisplayName: identity.DisplayName,
		AvatarURL:   identity.AvatarURL,
	}
}

func normalizeAccountProviderIdentity(identity AccountProviderIdentity) (AccountProviderIdentity, error) {
	provider := strings.ToLower(strings.TrimSpace(identity.Provider))
	if provider == "" {
		return AccountProviderIdentity{}, errors.New("account.provider.missing_provider")
	}
	subject := strings.TrimSpace(identity.Subject)
	if subject == "" {
		return AccountProviderIdentity{}, errors.New("account.provider.missing_subject")
	}
	normalizedEmail, emailErr := normalizePasswordEmail(identity.UserEmail)
	if emailErr != nil {
		return AccountProviderIdentity{}, emailErr
	}
	return AccountProviderIdentity{
		Provider:    provider,
		Subject:     subject,
		UserEmail:   normalizedEmail,
		DisplayName: defaultDisplayName(identity.DisplayName, normalizedEmail),
		AvatarURL:   strings.TrimSpace(identity.AvatarURL),
	}, nil
}

func profileFromAccount(account *accountRecord) AccountProfile {
	if account == nil {
		return AccountProfile{}
	}
	return AccountProfile{
		AccountID:   account.accountID,
		UserEmail:   account.userEmail,
		DisplayName: account.displayName,
		AvatarURL:   account.avatarURL,
		Roles:       append([]string(nil), account.roles...),
		State:       account.state,
	}
}

func identityKey(provider string, providerID string) string {
	return strings.ToLower(strings.TrimSpace(provider)) + "::" + strings.TrimSpace(providerID)
}

func defaultDisplayName(displayName string, email string) string {
	trimmedDisplayName := strings.TrimSpace(displayName)
	if trimmedDisplayName != "" {
		return trimmedDisplayName
	}
	return email
}
