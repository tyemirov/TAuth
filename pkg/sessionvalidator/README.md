# Session Validator

The `sessionvalidator` package lets downstream Go services consume the session
cookie issued by TAuth. It verifies the HS256 signature, issuer, and time-based
claims, and can be wrapped as Gin middleware for easy route protection.

```go
package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
)

func main() {
	validator, err := sessionvalidator.New(sessionvalidator.Config{
		SigningKey: []byte(os.Getenv("APP_JWT_SIGNING_KEY")),
		Issuer:     "tauth",
		// CookieName defaults to app_session.
	})
	if err != nil {
		log.Fatalf("invalid validator configuration: %v", err)
	}

	router := gin.Default()
	router.Use(validator.GinMiddleware("claims"))
	router.GET("/me", func(context *gin.Context) {
		claimsValue, _ := context.Get("claims")
		claims := claimsValue.(*sessionvalidator.Claims)
		context.JSON(200, gin.H{
			"user_id": claims.GetUserID(),
			"email":   claims.GetUserEmail(),
		})
	})
	_ = router.Run()
}
```

## Features

- Smart constructor validates configuration up front.
- `ValidateToken` and `ValidateRequest` helpers for manual flows.
- Gin middleware adapter with configurable context key.
- Exposes typed claims struct matching TAuth’s JWT payload (user id, email,
  display name, avatar URL, roles, expiry metadata).

## Testing

```bash
go test ./pkg/sessionvalidator/...
```
