package authkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
	"go.uber.org/zap"
)

// GitHubAuthorizationContinuation validates a current pending OAuth request.
type GitHubAuthorizationContinuation interface {
	GitHubAuthorization(context.Context, string, string) (string, error)
}

// GitHubLogin owns the browser protocol for session login, account links, and OAuth login.
type GitHubLogin struct {
	sessions     *OAuthBrowserSessions
	transactions GitHubTransactionStore
	provider     *GitHubProvider
	continuation GitHubAuthorizationContinuation
}

// NewGitHubLogin connects GitHub authentication to the current session and transaction stores.
func NewGitHubLogin(sessions *OAuthBrowserSessions, transactions GitHubTransactionStore, provider *GitHubProvider, continuation GitHubAuthorizationContinuation) (*GitHubLogin, error) {
	if sessions == nil || sessions.users == nil || sessions.refreshTokens == nil || transactions == nil || provider == nil {
		return nil, errors.New("github_login.invalid_dependencies")
	}
	return &GitHubLogin{sessions: sessions, transactions: transactions, provider: provider, continuation: continuation}, nil
}

// Mount registers provider protocol routes outside browser Origin middleware.
func (login *GitHubLogin) Mount(router gin.IRouter) {
	router.GET(tenants.GitHubStartPath, gin.WrapF(login.start))
	router.GET(tenants.GitHubCallbackPath, gin.WrapF(login.callback))
}

// RedactGitHubCallbackQuery removes callback credentials before outer recovery logging.
func RedactGitHubCallbackQuery() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.Request.URL.Path == tenants.GitHubCallbackPath {
			defer func() {
				clean := *ctx.Request.URL
				clean.RawQuery = ""
				clean.ForceQuery = false
				ctx.Request.URL = &clean
				ctx.Request.RequestURI = clean.RequestURI()
				ctx.Request.Header = ctx.Request.Header.Clone()
				ctx.Request.Header.Del("Cookie")
				ctx.Request.Header.Del("Authorization")
			}()
		}
		ctx.Next()
	}
}

func (login *GitHubLogin) start(response http.ResponseWriter, request *http.Request) {
	githubPrivateHeaders(response)
	query := request.URL.Query()
	if !githubQueryValid(query, "tenant_id", "return_to", "operation", "oauth_request", "popup", "correlation") {
		githubError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	tenantID := query.Get("tenant_id")
	if tenantID == "" {
		origin := githubURLOrigin(query.Get("return_to"))
		for candidateID, config := range login.sessions.registry.configs {
			if slices.Contains(config.TenantOrigins, origin) {
				if tenantID != "" {
					githubError(response, http.StatusBadRequest, "missing_tenant")
					return
				}
				tenantID = candidateID
			}
		}
	}
	config, exists := login.sessions.registry.ConfigByID(tenantID)
	if !exists || !config.GitHubOAuth.Enabled() {
		githubError(response, http.StatusNotFound, "github_login_not_configured")
		return
	}
	if !isHTTPS(request) {
		githubError(response, http.StatusBadRequest, "https_required")
		return
	}
	transaction := githubTransaction{TenantID: tenantID, ClientID: config.GitHubOAuth.ClientID(), RedirectURI: config.GitHubOAuth.RedirectURI(), Operation: githubSessionLogin}
	switch query.Get("operation") {
	case "", string(githubSessionLogin):
	case string(githubAccountLink):
		transaction.Operation = githubAccountLink
	case string(githubOAuthContinuation):
		transaction.Operation = githubOAuthContinuation
	default:
		githubError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if transaction.Operation == githubOAuthContinuation {
		if login.continuation == nil || query.Get("return_to") != "" || query.Get("popup") != "" {
			githubError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		transaction.OAuthRequest = query.Get("oauth_request")
		destination, err := login.continuation.GitHubAuthorization(request.Context(), tenantID, transaction.OAuthRequest)
		if err != nil {
			githubError(response, http.StatusBadRequest, "invalid_oauth_request")
			return
		}
		transaction.ReturnTo = destination
	} else {
		if query.Get("oauth_request") != "" || !githubReturnToAllowed(query.Get("return_to"), config.TenantOrigins) {
			githubError(response, http.StatusBadRequest, "invalid_return_to")
			return
		}
		transaction.ReturnTo = query.Get("return_to")
	}
	if origin := request.Header.Get("Origin"); origin != "" && origin != githubURLOrigin(transaction.ReturnTo) {
		githubError(response, http.StatusBadRequest, "invalid_origin")
		return
	}
	if transaction.Operation == githubAccountLink {
		accountID, authenticated, err := login.sessions.Resolve(request, tenantID)
		if err != nil {
			githubError(response, http.StatusInternalServerError, "store_failure")
			return
		}
		if !config.AccountManagementEnabled || !authenticated {
			githubError(response, http.StatusUnauthorized, "authentication_required")
			return
		}
		transaction.AccountID = accountID
	}
	if query.Get("popup") != "" {
		if query.Get("popup") != "true" || !githubOpaqueValid(query.Get("correlation")) {
			githubError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		transaction.PopupOrigin = githubURLOrigin(transaction.ReturnTo)
		transaction.Correlation = query.Get("correlation")
	} else if query.Get("correlation") != "" {
		githubError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	state, stateHash, err := generateOpaqueToken(rand.Reader, 32, "github_login.state")
	if err != nil {
		githubError(response, http.StatusInternalServerError, "store_failure")
		return
	}
	browser, browserHash, err := generateOpaqueToken(rand.Reader, 32, "github_login.browser")
	if err != nil {
		githubError(response, http.StatusInternalServerError, "store_failure")
		return
	}
	verifier, _, err := generateOpaqueToken(rand.Reader, 32, "github_login.pkce")
	if err != nil {
		githubError(response, http.StatusInternalServerError, "store_failure")
		return
	}
	now := login.sessions.clock.Now().UTC()
	transaction.StateHash, transaction.BrowserHash, transaction.Verifier = stateHash, browserHash, verifier
	transaction.CreatedAtUnix, transaction.ExpiresAtUnix = now.Unix(), now.Add(githubTransactionTTL).Unix()
	if err := login.transactions.create(request.Context(), transaction); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrGitHubStoreFull) {
			status = http.StatusServiceUnavailable
		}
		githubError(response, status, "store_failure")
		return
	}
	http.SetCookie(response, &http.Cookie{Name: githubBrowserCookie(state), Value: browser, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: int(githubTransactionTTL.Seconds())})
	challenge := sha256.Sum256([]byte(verifier))
	parameters := url.Values{"client_id": {transaction.ClientID}, "redirect_uri": {transaction.RedirectURI}, "scope": {tenants.GitHubIdentityScope}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(response, request, login.provider.authorizationEndpoint+"?"+parameters.Encode(), http.StatusFound)
}

func (login *GitHubLogin) callback(response http.ResponseWriter, request *http.Request) {
	githubPrivateHeaders(response)
	query := request.URL.Query()
	state := query.Get("state")
	if !githubQueryValid(query, "state", "code", "error", "error_description", "error_uri", "tenant_id") || !githubOpaqueValid(state) {
		githubError(response, http.StatusBadRequest, "invalid_state")
		return
	}
	browser, err := request.Cookie(githubBrowserCookie(state))
	if err != nil || !githubOpaqueValid(browser.Value) || !isHTTPS(request) {
		githubError(response, http.StatusBadRequest, "invalid_state")
		return
	}
	transaction, err := login.transactions.claim(request.Context(), hashOpaque(state), hashOpaque(browser.Value), login.sessions.clock.Now().Unix())
	if err != nil {
		status, code := http.StatusInternalServerError, "store_failure"
		if errors.Is(err, ErrGitHubStateInvalid) {
			status, code = http.StatusBadRequest, "invalid_state"
		}
		githubError(response, status, code)
		return
	}
	http.SetCookie(response, &http.Cookie{Name: githubBrowserCookie(state), Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	config, exists := login.sessions.registry.ConfigByID(transaction.TenantID)
	if !exists || !config.GitHubOAuth.Enabled() || config.GitHubOAuth.ClientID() != transaction.ClientID || config.GitHubOAuth.RedirectURI() != transaction.RedirectURI ||
		(query.Get("tenant_id") != "" && query.Get("tenant_id") != transaction.TenantID) || (request.Header.Get("X-TAuth-Tenant") != "" && request.Header.Get("X-TAuth-Tenant") != transaction.TenantID) ||
		githubURLOrigin(transaction.RedirectURI) != "https://"+request.Host ||
		(transaction.Operation == githubAccountLink && !config.AccountManagementEnabled) ||
		(transaction.Operation != githubOAuthContinuation && !githubReturnToAllowed(transaction.ReturnTo, config.TenantOrigins)) {
		login.failure(response, request, transaction, http.StatusBadRequest, "invalid_state")
		return
	}
	if !login.continuationValid(request.Context(), transaction) {
		login.failure(response, request, transaction, http.StatusBadRequest, "invalid_oauth_request")
		return
	}
	if transaction.Operation == githubAccountLink {
		active, err := login.sessions.ActiveUser(request.Context(), transaction.TenantID, transaction.AccountID)
		if err != nil {
			login.failure(response, request, transaction, http.StatusInternalServerError, "store_failure")
			return
		}
		if !active {
			login.failure(response, request, transaction, http.StatusForbidden, errorAccountDisabled)
			return
		}
	}
	if query.Get("error") != "" {
		login.failure(response, request, transaction, http.StatusForbidden, "github_consent_denied")
		return
	}
	if query.Get("code") == "" {
		login.failure(response, request, transaction, http.StatusBadRequest, "invalid_request")
		return
	}
	identity, err := login.provider.identity(request.Context(), config.GitHubOAuth, transaction, query.Get("code"))
	if err != nil {
		code := "github_provider_rejected"
		if errors.Is(err, ErrGitHubEmailMissing) {
			code = "github_verified_email_required"
		}
		login.failure(response, request, transaction, http.StatusBadGateway, code)
		return
	}
	if !isAllowedUser(identity.UserEmail, config.AllowedUsers) {
		login.failure(response, request, transaction, http.StatusForbidden, errorUserNotAllowed)
		return
	}
	if !login.continuationValid(request.Context(), transaction) {
		login.failure(response, request, transaction, http.StatusBadRequest, "invalid_oauth_request")
		return
	}
	profile, err := login.sessions.githubApplicationProfile(request.Context(), config, transaction, identity)
	if err != nil {
		status, code := http.StatusInternalServerError, "store_failure"
		switch {
		case errors.Is(err, ErrAccountExists):
			status, code = http.StatusConflict, errorAccountExists
		case errors.Is(err, ErrAccountDisabled), errors.Is(err, ErrAccountNotActive):
			status, code = http.StatusForbidden, errorAccountDisabled
		}
		login.failure(response, request, transaction, status, code)
		return
	}
	active, activeErr := login.sessions.ActiveUser(request.Context(), transaction.TenantID, profile.applicationUserID)
	if activeErr != nil {
		login.failure(response, request, transaction, http.StatusInternalServerError, "store_failure")
		return
	}
	if !active {
		login.failure(response, request, transaction, http.StatusForbidden, errorAccountDisabled)
		return
	}
	if err := login.sessions.writeBrowserSession(request.Context(), response, config, transaction.TenantID, profile); err != nil {
		login.failure(response, request, transaction, http.StatusInternalServerError, "store_failure")
		return
	}
	if transaction.PopupOrigin != "" {
		githubPopup(response, transaction, "complete")
		return
	}
	if transaction.Operation == githubOAuthContinuation {
		githubOAuthCompletion(response, transaction.ReturnTo)
		return
	}
	http.Redirect(response, request, transaction.ReturnTo, http.StatusSeeOther)
}

func (login *GitHubLogin) continuationValid(ctx context.Context, transaction githubTransaction) bool {
	if transaction.Operation != githubOAuthContinuation {
		return true
	}
	if login.continuation == nil {
		return false
	}
	destination, err := login.continuation.GitHubAuthorization(ctx, transaction.TenantID, transaction.OAuthRequest)
	return err == nil && destination == transaction.ReturnTo
}

func (sessions *OAuthBrowserSessions) githubApplicationProfile(ctx context.Context, config ServerConfig, transaction githubTransaction, identity AccountProviderIdentity) (authenticatedSessionProfile, error) {
	if config.AccountManagementEnabled {
		if sessions.accountStore == nil {
			return authenticatedSessionProfile{}, errors.New("github_login.account_store_missing")
		}
		var account AccountProfile
		var err error
		if transaction.Operation == githubAccountLink {
			account, err = sessions.accountStore.LinkProviderIdentity(ctx, transaction.TenantID, transaction.AccountID, identity)
		} else {
			account, err = sessions.accountStore.UpsertProviderAccount(ctx, transaction.TenantID, identity)
		}
		if err != nil {
			return authenticatedSessionProfile{}, err
		}
		if account.State != accountStateActive {
			return authenticatedSessionProfile{}, ErrAccountNotActive
		}
		userID, roles, err := sessions.users.UpsertAccountUser(ctx, transaction.TenantID, account.AccountID, account.UserEmail, account.DisplayName, account.AvatarURL)
		if err != nil {
			return authenticatedSessionProfile{}, err
		}
		return authenticatedSessionProfile{applicationUserID: userID, userEmail: account.UserEmail, userDisplayName: account.DisplayName, userAvatarURL: account.AvatarURL, userRoles: roles}, nil
	}
	userID, roles, err := sessions.users.UpsertProviderUser(ctx, transaction.TenantID, identity.Provider, identity.Subject, identity.UserEmail, identity.DisplayName, identity.AvatarURL)
	if err != nil {
		return authenticatedSessionProfile{}, err
	}
	return authenticatedSessionProfile{applicationUserID: userID, userEmail: identity.UserEmail, userDisplayName: identity.DisplayName, userAvatarURL: identity.AvatarURL, userRoles: roles}, nil
}

func (login *GitHubLogin) failure(response http.ResponseWriter, request *http.Request, transaction githubTransaction, status int, code string) {
	logAuthWarning("auth.github.callback", nil, zap.String("tenant", transaction.TenantID), zap.String("operation", string(transaction.Operation)), zap.String("correlation_id", transaction.StateHash[:16]), zap.String("code", code))
	if transaction.PopupOrigin != "" {
		githubPopup(response, transaction, code)
		return
	}
	githubError(response, status, code)
}

func githubQueryValid(query url.Values, allowed ...string) bool {
	for name, values := range query {
		if !slices.Contains(allowed, name) || len(values) != 1 || len(values[0]) > 4096 {
			return false
		}
	}
	return true
}

func githubOpaqueValid(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func githubBrowserCookie(state string) string { return "__Host-tauth_github_" + hashOpaque(state)[:16] }

func githubURLOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func githubReturnToAllowed(value string, origins []string) bool {
	return !strings.ContainsAny(value, "\\\r\n") && slices.Contains(origins, githubURLOrigin(value))
}

func githubPrivateHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
}

func githubError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code})
}

var githubPopupPage = template.Must(template.New("github-popup").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>GitHub sign-in</title><p id="status">{{.Message}}</p><script nonce="{{.Nonce}}">if(window.opener){window.opener.postMessage({type:"tauth:github",correlation:{{.Correlation}},status:{{.Status}}},{{.Origin}});window.close();}</script></html>`))

var githubOAuthCompletionPage = template.Must(template.New("github-oauth-completion").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>GitHub sign-in complete</title><p>GitHub sign-in is complete.</p><a id="github-continue" href="{{.Destination}}">Continue</a><script nonce="{{.Nonce}}">window.addEventListener("pageshow",function(){window.location.replace(document.getElementById("github-continue").href);});</script></html>`))

// A committed TAuth document starts a same-site navigation. A provider redirect
// chain cannot send Strict session cookies to the consent endpoint.
func githubOAuthCompletion(response http.ResponseWriter, destination string) {
	nonce, _, err := generateOpaqueToken(rand.Reader, 32, "github_completion.nonce")
	if err != nil {
		githubError(response, http.StatusInternalServerError, "store_failure")
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'")
	_ = githubOAuthCompletionPage.Execute(response, struct{ Nonce, Destination string }{nonce, destination})
}

func githubPopup(response http.ResponseWriter, transaction githubTransaction, status string) {
	nonce, _, err := generateOpaqueToken(rand.Reader, 32, "github_popup.nonce")
	if err != nil {
		githubError(response, http.StatusInternalServerError, "store_failure")
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'")
	message := "GitHub sign-in failed. Close this window and try again."
	if status == "complete" {
		message = "GitHub sign-in is complete. You can close this window."
	}
	_ = githubPopupPage.Execute(response, struct{ Nonce, Correlation, Origin, Status, Message string }{nonce, transaction.Correlation, transaction.PopupOrigin, status, message})
}
