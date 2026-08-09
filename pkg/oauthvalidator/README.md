# OAuth Access-Token Validator

Use `oauthvalidator` in a Go protected resource that accepts TAuth OAuth access
tokens. The validator requires one issuer, one resource audience, a verification
key source, and an optional required scope set.

```go
package main

import (
	"net/http"

	"github.com/tyemirov/tauth/pkg/oauthvalidator"
)

func main() {
	validator, err := oauthvalidator.New(oauthvalidator.Config{
		Issuer:         "https://auth.example.com",
		Audience:       "https://api.example.com",
		RequiredScopes: []string{"documents:read"},
		JWKSURL:        "https://auth.example.com/oauth/jwks",
	})
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/documents", func(response http.ResponseWriter, request *http.Request) {
		claims, validateErr := validator.ValidateRequest(request)
		if validateErr != nil {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = claims.Subject
		_ = claims.ClientID
		_ = claims.TenantID
		response.WriteHeader(http.StatusNoContent)
	})
	_ = http.ListenAndServe(":8080", nil)
}
```

The validator accepts only ES256 tokens with `typ=at+jwt` and a known `kid`.
It validates the issuer, exact audience, expiry, issued-at claim, subject,
client ID, tenant ID, consent grant ID, and every required scope. A static
`JWKSet` is also accepted when the application already gets keys through a
trusted configuration channel.

Revocation stops refresh and revokes the consent grant at TAuth. A previously
issued access token remains valid until its short expiry. Set a bounded tenant
`access_token_ttl` and do not use this package as an introspection substitute.

Keep protected-resource metadata and domain authorization in the resource
server. TAuth verifies the OAuth grant. The resource still decides which
operations the validated subject can do.
