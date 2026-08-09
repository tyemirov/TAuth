package oauthserver

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestOAuthStoreContract(t *testing.T) {
	constructors := map[string]func(*testing.T) Store{
		"memory": func(testingHandle *testing.T) Store { return NewMemoryStore() },
		"sqlite": func(testingHandle *testing.T) Store {
			store, storeErr := NewDatabaseStore(context.Background(), "sqlite://"+filepath.Join(testingHandle.TempDir(), "oauth.db"))
			if storeErr != nil {
				testingHandle.Fatalf("open database store: %v", storeErr)
			}
			return store
		},
	}
	for name, constructor := range constructors {
		t.Run(name, func(t *testing.T) {
			assertOAuthStoreContract(t, constructor(t))
		})
	}
}

func assertOAuthStoreContract(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	pending := AuthorizationRequest{TenantID: "tenant-a", ClientID: "client-a", ExpiresAtUnix: 200}
	requestToken, requestErr := store.CreateAuthorizationRequest(ctx, pending)
	if requestErr != nil {
		t.Fatalf("create request: %v", requestErr)
	}
	if _, getErr := store.GetAuthorizationRequest(ctx, requestToken, 100); getErr != nil {
		t.Fatalf("get request: %v", getErr)
	}
	if _, expiryErr := store.GetAuthorizationRequest(ctx, requestToken, 200); !errors.Is(expiryErr, ErrAuthorizationRequestInvalid) {
		t.Fatalf("expected request expiry, got %v", expiryErr)
	}
	consumableToken, consumableErr := store.CreateAuthorizationRequest(ctx, AuthorizationRequest{TenantID: "tenant-a", ClientID: "client-a", ExpiresAtUnix: 300})
	if consumableErr != nil {
		t.Fatalf("create consumable request: %v", consumableErr)
	}
	consumedRequest, consumeErr := store.ConsumeAuthorizationRequest(ctx, consumableToken, 200)
	if consumeErr != nil || consumedRequest.TenantID != "tenant-a" || consumedRequest.ClientID != "client-a" {
		t.Fatalf("consume request: request=%#v err=%v", consumedRequest, consumeErr)
	}
	if _, replayErr := store.ConsumeAuthorizationRequest(ctx, consumableToken, 201); !errors.Is(replayErr, ErrAuthorizationRequestInvalid) {
		t.Fatalf("expected request replay rejection, got %v", replayErr)
	}

	consent, consentErr := store.SaveConsent(ctx, Consent{
		ConsentKey:    ConsentKey{TenantID: "tenant-a", UserID: "user-a", ClientID: "client-a", Resource: "https://resource.example", Scope: "resource:use"},
		CreatedAtUnix: 100, ExpiresAtUnix: 1000,
	})
	if consentErr != nil {
		t.Fatalf("save consent: %v", consentErr)
	}
	if found, exists, findErr := store.FindConsent(ctx, consent.ConsentKey, 200); findErr != nil || !exists || found.ID != consent.ID {
		t.Fatalf("find consent: exists=%v err=%v", exists, findErr)
	}
	for _, isolatedKey := range []ConsentKey{
		{TenantID: "tenant-b", UserID: "user-a", ClientID: "client-a", Resource: "https://resource.example", Scope: "resource:use"},
		{TenantID: "tenant-a", UserID: "user-b", ClientID: "client-a", Resource: "https://resource.example", Scope: "resource:use"},
	} {
		if isolated, exists, findErr := store.FindConsent(ctx, isolatedKey, 200); findErr != nil || exists || isolated.ID != "" {
			t.Fatalf("expected tenant and user consent isolation: exists=%v err=%v", exists, findErr)
		}
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	grant := AuthorizationGrant{
		ConsentID: consent.ID, TenantID: "tenant-a", UserID: "user-a", ClientID: "client-a",
		RedirectURI: "https://client.example/callback", Resource: "https://resource.example",
		Scope: "resource:use", CodeChallenge: pkceChallenge(verifier), ExpiresAtUnix: 500,
	}
	code, codeErr := store.IssueAuthorizationCode(ctx, grant)
	if codeErr != nil {
		t.Fatalf("issue code: %v", codeErr)
	}
	if _, wrongErr := store.RedeemAuthorizationCode(ctx, code, CodeExchange{
		ClientID: "client-b", Resource: grant.Resource, CodeVerifier: verifier, NowUnix: 200,
	}); !errors.Is(wrongErr, ErrAuthorizationCodeInvalid) {
		t.Fatalf("expected cross-client rejection, got %v", wrongErr)
	}
	if _, wrongResourceErr := store.RedeemAuthorizationCode(ctx, code, CodeExchange{
		ClientID: grant.ClientID, Resource: "https://other.example", CodeVerifier: verifier, NowUnix: 200,
	}); !errors.Is(wrongResourceErr, ErrAuthorizationCodeInvalid) {
		t.Fatalf("expected cross-resource rejection, got %v", wrongResourceErr)
	}
	exchanged, exchangeErr := store.RedeemAuthorizationCode(ctx, code, CodeExchange{
		ClientID: grant.ClientID, Resource: grant.Resource, CodeVerifier: verifier, NowUnix: 200,
	})
	if exchangeErr != nil || exchanged.TenantID != grant.TenantID || exchanged.UserID != grant.UserID {
		t.Fatalf("redeem code: %v", exchangeErr)
	}
	if _, replayErr := store.RedeemAuthorizationCode(ctx, code, CodeExchange{
		ClientID: grant.ClientID, Resource: grant.Resource, CodeVerifier: verifier, NowUnix: 201,
	}); !errors.Is(replayErr, ErrAuthorizationCodeInvalid) {
		t.Fatalf("expected code replay rejection, got %v", replayErr)
	}
	expiringCode, expiringCodeErr := store.IssueAuthorizationCode(ctx, grant)
	if expiringCodeErr != nil {
		t.Fatalf("issue expiring code: %v", expiringCodeErr)
	}
	if _, expiryErr := store.RedeemAuthorizationCode(ctx, expiringCode, CodeExchange{
		ClientID: grant.ClientID, Resource: grant.Resource, CodeVerifier: verifier, NowUnix: grant.ExpiresAtUnix,
	}); !errors.Is(expiryErr, ErrAuthorizationCodeInvalid) {
		t.Fatalf("expected code expiry, got %v", expiryErr)
	}

	refreshGrant := RefreshGrant{
		ConsentID: consent.ID, TenantID: grant.TenantID, UserID: grant.UserID,
		ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope, ExpiresAtUnix: 900,
	}
	refreshToken, refreshErr := store.IssueRefreshToken(ctx, refreshGrant)
	if refreshErr != nil {
		t.Fatalf("issue refresh: %v", refreshErr)
	}
	if _, _, crossClientErr := store.RotateRefreshToken(ctx, refreshToken, "client-b", grant.Resource, "", 300); !errors.Is(crossClientErr, ErrRefreshTokenInvalid) {
		t.Fatalf("expected refresh cross-client rejection, got %v", crossClientErr)
	}
	if _, _, crossResourceErr := store.RotateRefreshToken(ctx, refreshToken, grant.ClientID, "https://other.example", "", 300); !errors.Is(crossResourceErr, ErrRefreshTokenInvalid) {
		t.Fatalf("expected refresh cross-resource rejection, got %v", crossResourceErr)
	}
	if _, _, scopeErr := store.RotateRefreshToken(ctx, refreshToken, grant.ClientID, grant.Resource, "other:scope", 300); !errors.Is(scopeErr, ErrRefreshTokenScope) {
		t.Fatalf("expected refresh scope rejection, got %v", scopeErr)
	}
	rotatedGrant, rotatedToken, rotateErr := store.RotateRefreshToken(ctx, refreshToken, grant.ClientID, grant.Resource, grant.Scope, 300)
	if rotateErr != nil || rotatedGrant.TenantID != grant.TenantID || rotatedGrant.UserID != grant.UserID || rotatedToken == refreshToken {
		t.Fatalf("rotate refresh: %v", rotateErr)
	}
	if _, _, reuseErr := store.RotateRefreshToken(ctx, refreshToken, grant.ClientID, grant.Resource, "", 301); !errors.Is(reuseErr, ErrRefreshTokenReuse) {
		t.Fatalf("expected refresh reuse, got %v", reuseErr)
	}
	if _, _, familyErr := store.RotateRefreshToken(ctx, rotatedToken, grant.ClientID, grant.Resource, "", 302); !errors.Is(familyErr, ErrRefreshTokenInvalid) {
		t.Fatalf("expected family revocation, got %v", familyErr)
	}
	if activeConsent, exists, findErr := store.FindConsent(ctx, consent.ConsentKey, 302); findErr != nil || exists || activeConsent.ID != "" {
		t.Fatalf("expected revoked consent, exists=%v err=%v", exists, findErr)
	}
	expiringRefresh, expiringRefreshErr := store.IssueRefreshToken(ctx, RefreshGrant{
		ConsentID: consent.ID, TenantID: grant.TenantID, UserID: grant.UserID,
		ClientID: grant.ClientID, Resource: grant.Resource, Scope: grant.Scope, ExpiresAtUnix: 400,
	})
	if expiringRefreshErr != nil {
		t.Fatalf("issue expiring refresh token: %v", expiringRefreshErr)
	}
	if _, _, expiryErr := store.RotateRefreshToken(ctx, expiringRefresh, grant.ClientID, grant.Resource, "", 400); !errors.Is(expiryErr, ErrRefreshTokenInvalid) {
		t.Fatalf("expected refresh expiry, got %v", expiryErr)
	}
}
