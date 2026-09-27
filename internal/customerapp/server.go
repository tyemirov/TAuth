// Package customerapp implements the documented customer API integration example.
package customerapp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/tyemirov/tauth/pkg/sessionvalidator"
	"golang.org/x/net/publicsuffix"
)

// Config is the external backend configuration accepted by New.
type Config struct {
	UpstreamOrigin, APIOrigin, FrontendOrigin, TenantID, SessionCookie, SessionKeyBase64 string
	Clock                                                                                sessionvalidator.Clock
}

// New validates the backend inputs and creates the fixed proxy and protected API routes.
func New(input Config, transport http.RoundTripper) (http.Handler, error) {
	upstream, err := parseOrigin(input.UpstreamOrigin)
	if err != nil {
		return nil, err
	}
	api, err := parseOrigin(input.APIOrigin)
	if err != nil {
		return nil, err
	}
	frontend, err := parseOrigin(input.FrontendOrigin)
	if err != nil {
		return nil, err
	}
	if frontend.Scheme != api.Scheme {
		return nil, errors.New("customer API and frontend require the same scheme")
	}
	if frontend.Hostname() != api.Hostname() {
		frontendSite, frontendErr := publicsuffix.EffectiveTLDPlusOne(frontend.Hostname())
		apiSite, apiErr := publicsuffix.EffectiveTLDPlusOne(api.Hostname())
		if frontendErr != nil || apiErr != nil || frontendSite != apiSite {
			return nil, errors.New("customer API and frontend require the same cookie site")
		}
	}
	if input.TenantID == "" || input.SessionCookie == "" {
		return nil, errors.New("customer API requires tenant ID and session cookie name")
	}
	key, err := base64.StdEncoding.DecodeString(input.SessionKeyBase64)
	if err != nil {
		return nil, errors.New("customer API requires a base64 session key")
	}
	validator, err := sessionvalidator.New(sessionvalidator.Config{SigningKey: key, CookieName: input.SessionCookie, Clock: input.Clock})
	if err != nil {
		return nil, err
	}
	routes := map[string]string{"/auth/nonce": "POST", "/auth/google": "POST", "/auth/session": "GET", "/auth/refresh": "POST", "/auth/logout": "POST", "/me": "GET"}
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(upstream)
		request.Out.Header.Del("Forwarded")
		request.Out.Header.Del("Authorization")
		request.Out.Header.Set("X-TAuth-Tenant", input.TenantID)
		request.Out.Header.Set("X-Forwarded-Host", api.Host)
		request.Out.Header.Set("X-Forwarded-Proto", api.Scheme)
	}, ModifyResponse: func(response *http.Response) error {
		// The customer API owns its browser CORS policy. Do not append the
		// upstream service headers to the headers already set on this response.
		for name := range response.Header {
			if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
				response.Header.Del(name)
			}
		}
		cookies := response.Cookies()
		response.Header.Del("Set-Cookie")
		for _, cookie := range cookies {
			cookie.Domain = ""
			cookie.HttpOnly = true
			cookie.Secure = api.Scheme == "https"
			cookie.SameSite = http.SameSiteLaxMode
			response.Header.Add("Set-Cookie", cookie.String())
		}
		response.Header.Set("Cache-Control", "no-store")
		return nil
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Authentication service is unavailable", http.StatusBadGateway)
	}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Origin")
		if r.Header.Get("Origin") != input.FrontendOrigin {
			http.Error(w, "Origin denied", http.StatusForbidden)
			return
		}
		if requested := r.Header.Get("X-TAuth-Tenant"); requested != "" && requested != input.TenantID {
			http.Error(w, "Tenant denied", http.StatusForbidden)
			return
		}
		method, authRoute := routes[r.URL.Path]
		if r.URL.Path == "/private" {
			method = "GET"
		} else if !authRoute {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", input.FrontendOrigin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-TAuth-Tenant, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", method+", OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method+", OPTIONS")
			http.Error(w, "Method denied", http.StatusMethodNotAllowed)
			return
		}
		if authRoute {
			proxy.ServeHTTP(w, r)
			return
		}
		claims, err := validator.ValidateRequest(r)
		if err != nil {
			http.Error(w, "Sign in required", http.StatusUnauthorized)
			return
		}
		if claims.TenantID != input.TenantID {
			http.Error(w, "Tenant denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Protected API accepted this session.", "tenant_id": claims.TenantID, "user_id": claims.Subject}); err != nil {
			slog.Error("customerapp.write_response", "error", err)
		}
	}), nil
}
func parseOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Opaque != "" || parsed.ForceQuery {
		return nil, errors.New("customer API requires exact origins")
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return nil, errors.New("customer API requires HTTPS except loopback development")
	}
	return parsed, nil
}
