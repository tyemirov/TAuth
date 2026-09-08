package oauthvalidator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGitHubIdentityClaimShapeAtResource(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validator := mustValidator(t, Config{Issuer: "https://issuer.example", Audience: "https://resource.example", JWKSet: testJWKSet(t, &key.PublicKey, "active")})
	resource := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		claims, err := validator.ValidateRequest(request)
		if err != nil {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(response).Encode(claims)
	}))
	defer resource.Close()
	for _, value := range []string{
		`[{"provider":"github","provider_id":"9007199254740993"}]`,
		`[{"provider":"github","provider_id":9007199254740993}]`,
		`[{"provider":"github","provider_id":"01"}]`,
		`[{"provider":"github","provider_id":"0"}]`,
		`[{"provider":"github","provider_id":"-1"}]`,
		`[{"provider":"github","provider_id":"1","token":"secret"}]`,
		`[{"provider":"other","provider_id":"1"}]`,
		`[{"provider":"github","provider_id":"1","provider_id":"2"}]`,
		`[{"provider":"github","provider_id":"1"},{"provider":"github","provider_id":"1"}]`,
		`[]`, `null`,
	} {
		t.Run(value, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "https://issuer.example", "aud": "https://resource.example", "sub": "account-1", "client_id": "client-1", "tenant_id": "demo", "scope": "resource:use", "grant_id": "grant-1", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "provider_identities": json.RawMessage(value)}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"], token.Header["typ"] = "active", "at+jwt"
			signed, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodGet, resource.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+signed)
			response, err := resource.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			valid := value == `[{"provider":"github","provider_id":"9007199254740993"}]`
			if !valid {
				if response.StatusCode != 401 {
					t.Fatalf("invalid identity claim accepted: %d", response.StatusCode)
				}
				return
			}
			var decoded map[string]json.RawMessage
			if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if string(decoded["provider_identities"]) != value {
				t.Fatal("validated identity unavailable at resource")
			}
		})
	}
}
