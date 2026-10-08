package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrAuthorizationRequestInvalid = errors.New("oauth.authorization_request_invalid")
	ErrAuthorizationCapacity       = errors.New("oauth.authorization_capacity_exceeded")
	ErrAuthorizationCodeInvalid    = errors.New("oauth.authorization_code_invalid")
	ErrRefreshTokenInvalid         = errors.New("oauth.refresh_token_invalid")
	ErrRefreshTokenReuse           = errors.New("oauth.refresh_token_reuse")
	ErrRefreshTokenScope           = errors.New("oauth.refresh_token_scope")
)

const (
	maximumPendingPerTenant   = 1000
	maximumPendingGlobal      = 10000
	maximumRefreshPerTenant   = 100000
	maximumRefreshGlobal      = 1000000
	refreshTokenStatusActive  = "active"
	refreshTokenStatusRotated = "rotated"
	refreshTokenStatusRevoked = "revoked"
)

type memoryAuthorizationRequest struct {
	request AuthorizationRequest
}

type memoryAuthorizationCode struct {
	grant          AuthorizationGrant
	consumedAtUnix int64
}

type memoryRefreshToken struct {
	grant         RefreshGrant
	status        string
	issuedAtUnix  int64
	rotatedAtUnix int64
	revokedAtUnix int64
}

// MemoryStore is the in-memory OAuth transaction store for local operation and tests.
type MemoryStore struct {
	mu            sync.Mutex
	requests      map[string]memoryAuthorizationRequest
	codes         map[string]memoryAuthorizationCode
	consents      map[string]Consent
	refreshTokens map[string]memoryRefreshToken
}

// NewMemoryStore creates an empty OAuth transaction store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		requests:      make(map[string]memoryAuthorizationRequest),
		codes:         make(map[string]memoryAuthorizationCode),
		consents:      make(map[string]Consent),
		refreshTokens: make(map[string]memoryRefreshToken),
	}
}

// CreateAuthorizationRequest stores a validated request under an opaque handle.
func (store *MemoryStore) CreateAuthorizationRequest(ctx context.Context, request AuthorizationRequest) (string, error) {
	token, digest, tokenErr := newOpaqueToken("authorization_request")
	if tokenErr != nil {
		return "", tokenErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(request.CreatedAtUnix)
	tenantCount := 0
	for _, existing := range store.requests {
		if existing.request.TenantID == request.TenantID {
			tenantCount++
		}
	}
	if tenantCount >= maximumPendingPerTenant || len(store.requests) >= maximumPendingGlobal {
		return "", ErrAuthorizationCapacity
	}
	store.requests[digest] = memoryAuthorizationRequest{request: request}
	return token, nil
}

// GetAuthorizationRequest returns one unexpired pending authorization request.
func (store *MemoryStore) GetAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	digest := digestToken(requestToken)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	record, exists := store.requests[digest]
	if !exists || record.request.ExpiresAtUnix <= nowUnix {
		delete(store.requests, digest)
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	return record.request, nil
}

// ConsumeAuthorizationRequest atomically returns and removes one unexpired request.
func (store *MemoryStore) ConsumeAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	digest := digestToken(requestToken)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	record, exists := store.requests[digest]
	if !exists || record.request.ExpiresAtUnix <= nowUnix {
		delete(store.requests, digest)
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	delete(store.requests, digest)
	return record.request, nil
}

// CompleteAuthorizationRequest commits the request, consent, and code together.
func (store *MemoryStore) CompleteAuthorizationRequest(ctx context.Context, requestToken string, completion AuthorizationCompletion) (string, error) {
	consent := completion.Consent
	createConsent := consent.ID == ""
	if createConsent {
		identifier, _, err := newOpaqueToken("consent")
		if err != nil {
			return "", err
		}
		consent.ID = identifier
	}
	code, codeDigest, err := newOpaqueToken("authorization_code")
	if err != nil {
		return "", err
	}
	requestDigest := digestToken(requestToken)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("oauth_store.request.complete.memory: %w", err)
	}
	store.cleanupExpiredLocked(completion.NowUnix)
	if store.codeCapacityLocked(completion.Grant.TenantID) {
		return "", ErrAuthorizationCapacity
	}
	record, exists := store.requests[requestDigest]
	if !exists || record.request.ExpiresAtUnix <= completion.NowUnix || record.request != completion.Request {
		return "", ErrAuthorizationRequestInvalid
	}
	grant := completion.Grant
	grant.ConsentID = consent.ID
	if createConsent {
		store.consents[consent.ID] = consent
	}
	store.codes[codeDigest] = memoryAuthorizationCode{grant: grant}
	delete(store.requests, requestDigest)
	return code, nil
}

// FindConsent returns one active exact consent grant.
func (store *MemoryStore) FindConsent(ctx context.Context, key ConsentKey, nowUnix int64) (Consent, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	for _, consent := range store.consents {
		if consent.ConsentKey != key || consent.RevokedAtUnix != 0 || consent.ExpiresAtUnix <= nowUnix {
			continue
		}
		return consent, true, nil
	}
	return Consent{}, false, nil
}

// SaveConsent stores one approved exact consent grant.
func (store *MemoryStore) SaveConsent(ctx context.Context, consent Consent) (Consent, error) {
	if strings.TrimSpace(consent.ID) == "" {
		consentID, _, consentIDErr := newOpaqueToken("consent")
		if consentIDErr != nil {
			return Consent{}, consentIDErr
		}
		consent.ID = consentID
	}
	store.mu.Lock()
	store.cleanupExpiredLocked(consent.CreatedAtUnix)
	store.consents[consent.ID] = consent
	store.mu.Unlock()
	return consent, nil
}

// IssueAuthorizationCode stores one short-lived one-time code as a digest.
func (store *MemoryStore) IssueAuthorizationCode(ctx context.Context, grant AuthorizationGrant, nowUnix int64) (string, error) {
	code, digest, codeErr := newOpaqueToken("authorization_code")
	if codeErr != nil {
		return "", codeErr
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	if store.codeCapacityLocked(grant.TenantID) {
		return "", ErrAuthorizationCapacity
	}
	store.codes[digest] = memoryAuthorizationCode{grant: grant}
	return code, nil
}

// RedeemAuthorizationCode atomically consumes a bound code and creates its initial refresh family.
func (store *MemoryStore) RedeemAuthorizationCode(ctx context.Context, code string, exchange CodeExchange, authorize AccountAuthorization) (AuthorizationGrant, string, error) {
	digest := digestToken(code)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(exchange.NowUnix)
	record, exists := store.codes[digest]
	if !exists || record.consumedAtUnix != 0 || record.grant.ExpiresAtUnix <= exchange.NowUnix {
		return AuthorizationGrant{}, "", ErrAuthorizationCodeInvalid
	}
	if record.grant.ClientID != exchange.ClientID || record.grant.Resource != exchange.Resource {
		return AuthorizationGrant{}, "", ErrAuthorizationCodeInvalid
	}
	if !pkceVerifierMatches(record.grant.CodeChallenge, exchange.CodeVerifier) {
		return AuthorizationGrant{}, "", ErrAuthorizationCodeInvalid
	}
	if err := authorize(ctx, record.grant.TenantID, record.grant.UserID); err != nil {
		return AuthorizationGrant{}, "", err
	}
	if store.refreshCapacityLocked(record.grant.TenantID) {
		return AuthorizationGrant{}, "", ErrAuthorizationCapacity
	}
	refresh := refreshGrantForCode(record.grant, exchange.RefreshExpiresAtUnix)
	token, err := store.issueRefreshTokenLocked(refresh, exchange.NowUnix)
	if err != nil {
		return AuthorizationGrant{}, "", err
	}
	delete(store.codes, digest)
	return record.grant, token, nil
}

// IssueRefreshToken creates one opaque refresh-token family member and stores only its digest.
func (store *MemoryStore) IssueRefreshToken(ctx context.Context, grant RefreshGrant, nowUnix int64) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	if store.refreshCapacityLocked(grant.TenantID) {
		return "", ErrAuthorizationCapacity
	}
	return store.issueRefreshTokenLocked(grant, nowUnix)
}

func (store *MemoryStore) issueRefreshTokenLocked(grant RefreshGrant, nowUnix int64) (string, error) {
	if strings.TrimSpace(grant.FamilyID) == "" {
		familyID, _, familyErr := newOpaqueToken("refresh_family")
		if familyErr != nil {
			return "", familyErr
		}
		grant.FamilyID = familyID
	}
	token, digest, tokenErr := newOpaqueToken("refresh_token")
	if tokenErr != nil {
		return "", tokenErr
	}
	store.refreshTokens[digest] = memoryRefreshToken{grant: grant, status: refreshTokenStatusActive, issuedAtUnix: nowUnix}
	return token, nil
}

// RotateRefreshToken rotates an active family member and detects family reuse.
func (store *MemoryStore) RotateRefreshToken(ctx context.Context, refreshToken string, clientID string, resource string, scope string, nowUnix int64, authorize AccountAuthorization) (RefreshGrant, string, error) {
	digest := digestToken(refreshToken)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	record, exists := store.refreshTokens[digest]
	if !exists || record.grant.ClientID != clientID || record.grant.Resource != resource || record.grant.ExpiresAtUnix <= nowUnix {
		return RefreshGrant{}, "", ErrRefreshTokenInvalid
	}
	if scope != "" && record.grant.Scope != scope {
		return RefreshGrant{}, "", ErrRefreshTokenScope
	}
	if record.status == refreshTokenStatusRotated {
		store.revokeRefreshFamilyLocked(record.grant.FamilyID, record.grant.ConsentID, nowUnix)
		return RefreshGrant{}, "", ErrRefreshTokenReuse
	}
	if record.status != refreshTokenStatusActive || !store.consentActiveLocked(record.grant.ConsentID, nowUnix) {
		return RefreshGrant{}, "", ErrRefreshTokenInvalid
	}
	if err := authorize(ctx, record.grant.TenantID, record.grant.UserID); err != nil {
		return RefreshGrant{}, "", err
	}
	if store.refreshCapacityLocked(record.grant.TenantID) {
		return RefreshGrant{}, "", ErrAuthorizationCapacity
	}
	newToken, newDigest, tokenErr := newOpaqueToken("refresh_token")
	if tokenErr != nil {
		return RefreshGrant{}, "", tokenErr
	}
	record.status = refreshTokenStatusRotated
	record.rotatedAtUnix = nowUnix
	store.refreshTokens[digest] = record
	store.refreshTokens[newDigest] = memoryRefreshToken{grant: record.grant, status: refreshTokenStatusActive, issuedAtUnix: nowUnix}
	return record.grant, newToken, nil
}

// RevokeRefreshToken revokes the full family and its consent without revealing token existence.
func (store *MemoryStore) RevokeRefreshToken(ctx context.Context, refreshToken string, clientID string, nowUnix int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	record, exists := store.refreshTokens[digestToken(refreshToken)]
	if !exists || record.grant.ClientID != clientID {
		return nil
	}
	store.revokeRefreshFamilyLocked(record.grant.FamilyID, record.grant.ConsentID, nowUnix)
	return nil
}

// RevokeConsent revokes the consent and each refresh family bound to it.
func (store *MemoryStore) RevokeConsent(ctx context.Context, consentID string, nowUnix int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	store.revokeRefreshFamilyLocked("", consentID, nowUnix)
	return nil
}

// RevokeUser revokes all consents and refresh tokens and removes outstanding codes for one tenant and user.
func (store *MemoryStore) RevokeUser(ctx context.Context, tenantID string, userID string, nowUnix int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	for consentID, consent := range store.consents {
		if consent.TenantID == tenantID && consent.UserID == userID && consent.RevokedAtUnix == 0 {
			consent.RevokedAtUnix = nowUnix
			store.consents[consentID] = consent
		}
	}
	for digest, record := range store.refreshTokens {
		if record.grant.TenantID == tenantID && record.grant.UserID == userID {
			record.status = refreshTokenStatusRevoked
			record.revokedAtUnix = nowUnix
			store.refreshTokens[digest] = record
		}
	}
	for digest, record := range store.codes {
		if record.grant.TenantID == tenantID && record.grant.UserID == userID {
			delete(store.codes, digest)
		}
	}
	return nil
}

func (store *MemoryStore) consentActiveLocked(consentID string, nowUnix int64) bool {
	consent, exists := store.consents[consentID]
	return exists && consent.RevokedAtUnix == 0 && consent.ExpiresAtUnix > nowUnix
}

func (store *MemoryStore) revokeRefreshFamilyLocked(familyID string, consentID string, nowUnix int64) {
	for digest, record := range store.refreshTokens {
		familyMatches := familyID != "" && record.grant.FamilyID == familyID
		consentMatches := consentID != "" && record.grant.ConsentID == consentID
		if !familyMatches && !consentMatches {
			continue
		}
		record.status = refreshTokenStatusRevoked
		record.revokedAtUnix = nowUnix
		store.refreshTokens[digest] = record
	}
	if consentID == "" {
		return
	}
	consent, exists := store.consents[consentID]
	if exists && consent.RevokedAtUnix == 0 {
		consent.RevokedAtUnix = nowUnix
		store.consents[consentID] = consent
	}
}

func pkceVerifierMatches(challenge string, verifier string) bool {
	trimmedVerifier := strings.TrimSpace(verifier)
	if trimmedVerifier != verifier || len(trimmedVerifier) < 43 || len(trimmedVerifier) > 128 {
		return false
	}
	for _, character := range []byte(trimmedVerifier) {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~", rune(character)) {
			continue
		}
		return false
	}
	digest := sha256.Sum256([]byte(trimmedVerifier))
	derived := base64.RawURLEncoding.EncodeToString(digest[:])
	return derived == challenge
}

func validatePKCEChallenge(challenge string) error {
	trimmed := strings.TrimSpace(challenge)
	if len(trimmed) != 43 {
		return fmt.Errorf("oauth.pkce.invalid_challenge")
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(trimmed)
	if decodeErr != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("oauth.pkce.invalid_challenge")
	}
	return nil
}

// PurgeUser removes codes, consents, and refresh grants for one tenant and user.
func (store *MemoryStore) PurgeUser(ctx context.Context, tenantID, userID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("oauth_store.user_purge: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, consent := range store.consents {
		if consent.TenantID == tenantID && consent.UserID == userID {
			delete(store.consents, id)
		}
	}
	for id, record := range store.codes {
		if record.grant.TenantID == tenantID && record.grant.UserID == userID {
			delete(store.codes, id)
		}
	}
	for id, record := range store.refreshTokens {
		if record.grant.TenantID == tenantID && record.grant.UserID == userID {
			delete(store.refreshTokens, id)
		}
	}
	return nil
}

// CleanupExpired physically removes expired transient state and unreferenced inactive consents.
func (store *MemoryStore) CleanupExpired(ctx context.Context, nowUnix int64) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("oauth_store.cleanup: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked(nowUnix)
	return nil
}
func (store *MemoryStore) cleanupExpiredLocked(nowUnix int64) {
	for key, record := range store.requests {
		if record.request.ExpiresAtUnix <= nowUnix {
			delete(store.requests, key)
		}
	}
	for key, record := range store.codes {
		if record.grant.ExpiresAtUnix <= nowUnix || record.consumedAtUnix != 0 {
			delete(store.codes, key)
		}
	}
	for key, record := range store.refreshTokens {
		if record.grant.ExpiresAtUnix <= nowUnix {
			delete(store.refreshTokens, key)
		}
	}
	referenced := make(map[string]bool)
	for _, record := range store.codes {
		referenced[record.grant.ConsentID] = true
	}
	for _, record := range store.refreshTokens {
		referenced[record.grant.ConsentID] = true
	}
	for key, consent := range store.consents {
		if (consent.ExpiresAtUnix <= nowUnix || consent.RevokedAtUnix != 0) && !referenced[key] {
			delete(store.consents, key)
		}
	}
}
func (store *MemoryStore) codeCapacityLocked(tenantID string) bool {
	count := 0
	for _, record := range store.codes {
		if record.grant.TenantID == tenantID {
			count++
		}
	}
	return count >= maximumPendingPerTenant || len(store.codes) >= maximumPendingGlobal
}
func (store *MemoryStore) refreshCapacityLocked(tenantID string) bool {
	count := 0
	for _, record := range store.refreshTokens {
		if record.grant.TenantID == tenantID {
			count++
		}
	}
	return count >= maximumRefreshPerTenant || len(store.refreshTokens) >= maximumRefreshGlobal
}
func refreshGrantForCode(grant AuthorizationGrant, expiresAtUnix int64) RefreshGrant {
	return RefreshGrant{ConsentID: grant.ConsentID, TenantID: grant.TenantID, UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope, DisclosurePolicy: grant.DisclosurePolicy, ExpiresAtUnix: expiresAtUnix}
}
