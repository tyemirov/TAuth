// Package testsupport provides deterministic HTTP infrastructure for integration tests.
package testsupport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
)

// GitHub is a local OAuth App protocol server. Configure responses before a request.
type GitHub struct {
	Server      *httptest.Server
	UserJSON    string
	EmailsJSON  string
	TokenJSON   string
	TokenStatus int
	Calls       atomic.Int64
	mu          sync.Mutex
	codes       map[string]url.Values
	nextCode    int
}

// NewGitHub starts the deterministic provider.
func NewGitHub() *GitHub {
	provider := &GitHub{UserJSON: `{"id":9007199254740993,"login":"mutable-name","name":"GitHub User","avatar_url":"https://images.example/avatar.png"}`, EmailsJSON: `[{"email":"private@example.com","primary":true,"verified":true}]`, TokenJSON: `{"access_token":"provider-secret-token","token_type":"bearer","scope":"read:user,user:email"}`, TokenStatus: http.StatusOK, codes: make(map[string]url.Values)}
	provider.Server = httptest.NewServer(http.HandlerFunc(provider.serve))
	return provider
}

// RoundTrip maps fixed GitHub.com endpoints to the real local HTTP listener.
func (provider *GitHub) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "github.com" && request.URL.Host != "api.github.com" {
		return nil, fmt.Errorf("fixture.invalid_host")
	}
	endpoint, err := url.Parse(provider.Server.URL + request.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.URL, clone.Host = endpoint, endpoint.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func (provider *GitHub) serve(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/login/oauth/authorize":
		query := request.URL.Query()
		if query.Get("scope") != "read:user user:email" || query.Get("code_challenge_method") != "S256" {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		provider.mu.Lock()
		code := "provider-code-" + strconv.Itoa(provider.nextCode)
		provider.nextCode++
		provider.codes[code] = query
		provider.mu.Unlock()
		callback, err := url.Parse(query.Get("redirect_uri"))
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		callback.RawQuery = url.Values{"state": {query.Get("state")}, "code": {code}}.Encode()
		http.Redirect(response, request, callback.String(), http.StatusFound)
	case "/login/oauth/access_token":
		provider.Calls.Add(1)
		if err := request.ParseForm(); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		provider.mu.Lock()
		authorization, exists := provider.codes[request.PostForm.Get("code")]
		delete(provider.codes, request.PostForm.Get("code"))
		provider.mu.Unlock()
		challenge := sha256.Sum256([]byte(request.PostForm.Get("code_verifier")))
		if !exists || request.Method != http.MethodPost || request.PostForm.Get("client_secret") != "test-secret" || request.PostForm.Get("client_id") != authorization.Get("client_id") || request.PostForm.Get("redirect_uri") != authorization.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(challenge[:]) != authorization.Get("code_challenge") {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.WriteHeader(provider.TokenStatus)
		_, _ = response.Write([]byte(provider.TokenJSON))
	case "/user", "/user/emails":
		if request.Header.Get("Authorization") != "Bearer provider-secret-token" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path == "/user" {
			_, _ = response.Write([]byte(provider.UserJSON))
		} else {
			_, _ = response.Write([]byte(provider.EmailsJSON))
		}
	default:
		response.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(response).Encode(map[string]string{"error": "fixture_route_missing"})
	}
}
