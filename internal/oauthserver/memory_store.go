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
	ErrAuthorizationCodeInvalid    = errors.New("oauth.authorization_code_invalid")
	ErrRefreshTokenInvalid         = errors.New("oauth.refresh_token_invalid")
	ErrRefreshTokenReuse           = errors.New("oauth.refresh_token_reuse")
	ErrRefreshTokenScope           = errors.New("oauth.refresh_token_scope")
)

const (
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
	store.requests[digest] = memoryAuthorizationRequest{request: request}
	store.mu.Unlock()
	return token, nil
}

// GetAuthorizationRequest returns one unexpired pending authorization request.
func (store *MemoryStore) GetAuthorizationRequest(ctx context.Context, requestToken string, nowUnix int64) (AuthorizationRequest, error) {
	digest := digestToken(requestToken)
	store.mu.Lock()
	defer store.mu.Unlock()
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
	record, exists := store.requests[digest]
	if !exists || record.request.ExpiresAtUnix <= nowUnix {
		delete(store.requests, digest)
		return AuthorizationRequest{}, ErrAuthorizationRequestInvalid
	}
	delete(store.requests, digest)
	return record.request, nil
}

// FindConsent returns one active exact consent grant.
func (store *MemoryStore) FindConsent(ctx context.Context, key ConsentKey, nowUnix int64) (Consent, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.consents[consent.ID] = consent
	store.mu.Unlock()
	return consent, nil
}

// IssueAuthorizationCode stores one short-lived one-time code as a digest.
func (store *MemoryStore) IssueAuthorizationCode(ctx context.Context, grant AuthorizationGrant) (string, error) {
	code, digest, codeErr := newOpaqueToken("authorization_code")
	if codeErr != nil {
		return "", codeErr
	}
	store.mu.Lock()
	store.codes[digest] = memoryAuthorizationCode{grant: grant}
	store.mu.Unlock()
	return code, nil
}

// RedeemAuthorizationCode atomically validates every code binding and consumes the code.
func (store *MemoryStore) RedeemAuthorizationCode(ctx context.Context, code string, exchange CodeExchange) (AuthorizationGrant, error) {
	digest := digestToken(code)
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.codes[digest]
	if !exists || record.consumedAtUnix != 0 || record.grant.ExpiresAtUnix <= exchange.NowUnix {
		return AuthorizationGrant{}, ErrAuthorizationCodeInvalid
	}
	if record.grant.ClientID != exchange.ClientID || record.grant.Resource != exchange.Resource {
		return AuthorizationGrant{}, ErrAuthorizationCodeInvalid
	}
	if !pkceVerifierMatches(record.grant.CodeChallenge, exchange.CodeVerifier) {
		return AuthorizationGrant{}, ErrAuthorizationCodeInvalid
	}
	record.consumedAtUnix = exchange.NowUnix
	store.codes[digest] = record
	return record.grant, nil
}

// IssueRefreshToken creates one opaque refresh-token family member and stores only its digest.
func (store *MemoryStore) IssueRefreshToken(ctx context.Context, grant RefreshGrant) (string, error) {
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
	store.mu.Lock()
	store.refreshTokens[digest] = memoryRefreshToken{grant: grant, status: refreshTokenStatusActive}
	store.mu.Unlock()
	return token, nil
}

// RotateRefreshToken rotates an active family member and detects family reuse.
func (store *MemoryStore) RotateRefreshToken(ctx context.Context, refreshToken string, clientID string, resource string, scope string, nowUnix int64) (RefreshGrant, string, error) {
	digest := digestToken(refreshToken)
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.revokeRefreshFamilyLocked("", consentID, nowUnix)
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
