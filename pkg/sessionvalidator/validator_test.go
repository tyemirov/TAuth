package sessionvalidator

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type fixedClock struct {
	current time.Time
}

func (clock fixedClock) Now() time.Time {
	return clock.current
}

func mintToken(t *testing.T, signingKey []byte, issuer string, issuedAt time.Time, ttl time.Duration) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:          "user-123",
		UserEmail:       "user@example.com",
		UserDisplayName: "Demo User",
		UserAvatarURL:   "https://example.com/avatar.png",
		UserRoles:       []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-123",
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(ttl)),
		},
	})
	result, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return result
}

func TestNewValidatorRequiresSigningKey(t *testing.T) {
	t.Parallel()

	_, err := New(Config{Issuer: "issuer"})
	if err == nil || !errors.Is(err, ErrMissingSigningKey) {
		t.Fatalf("expected missing signing key error, got %v", err)
	}
}

func TestNewValidatorDefaults(t *testing.T) {
	t.Parallel()

	validator, err := New(Config{
		SigningKey: []byte("secret"),
		Issuer:     "issuer",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validator.cookieName != DefaultCookieName {
		t.Fatalf("expected default cookie name, got %s", validator.cookieName)
	}
	if validator.clock == nil {
		t.Fatalf("expected default clock to be set")
	}
}

func TestValidateTokenSuccess(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	validator, err := New(Config{
		SigningKey: []byte("secret-key"),
		Issuer:     "issuer",
		CookieName: "session",
		Clock:      fixedClock{current: now},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokenValue := mintToken(t, []byte("secret-key"), "issuer", now, time.Minute)

	claims, validateErr := validator.ValidateToken(tokenValue)
	if validateErr != nil {
		t.Fatalf("unexpected validation error: %v", validateErr)
	}
	if claims.GetUserID() != "user-123" || claims.GetUserEmail() != "user@example.com" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if !claims.GetExpiresAt().Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected expiry: %v", claims.GetExpiresAt())
	}
}

func TestValidateTokenRejectsInvalidCases(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	tests := []struct {
		name      string
		tokenFunc func() string
		expectErr error
	}{
		{
			name:      "empty token",
			tokenFunc: func() string { return "" },
			expectErr: ErrMissingToken,
		},
		{
			name: "bad signature",
			tokenFunc: func() string {
				return mintToken(t, []byte("other-key"), "issuer", now, time.Minute)
			},
			expectErr: ErrInvalidToken,
		},
		{
			name: "wrong issuer",
			tokenFunc: func() string {
				return mintToken(t, []byte("secret-key"), "other-issuer", now, time.Minute)
			},
			expectErr: ErrInvalidIssuer,
		},
		{
			name: "expired",
			tokenFunc: func() string {
				return mintToken(t, []byte("secret-key"), "issuer", now.Add(-2*time.Minute), time.Minute)
			},
			expectErr: ErrTokenExpired,
		},
	}

	validator, err := New(Config{
		SigningKey: []byte("secret-key"),
		Issuer:     "issuer",
		CookieName: "session",
		Clock:      fixedClock{current: now},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			_, validateErr := validator.ValidateToken(testCase.tokenFunc())
			if validateErr == nil || !errors.Is(validateErr, testCase.expectErr) {
				t.Fatalf("expected %v, got %v", testCase.expectErr, validateErr)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	tokenValue := mintToken(t, []byte("secret-key"), "issuer", now, time.Minute)
	validator, err := New(Config{
		SigningKey: []byte("secret-key"),
		Issuer:     "issuer",
		CookieName: "session",
		Clock:      fixedClock{current: now},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: tokenValue})
	claims, validateErr := validator.ValidateRequest(request)
	if validateErr != nil {
		t.Fatalf("unexpected validation error: %v", validateErr)
	}
	if claims.GetUserID() != "user-123" {
		t.Fatalf("unexpected user: %v", claims.GetUserID())
	}

	badRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	_, missingErr := validator.ValidateRequest(badRequest)
	if missingErr == nil || !errors.Is(missingErr, ErrMissingCookie) {
		t.Fatalf("expected missing cookie error, got %v", missingErr)
	}
}

func TestGinMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Unix(1700000000, 0).UTC()
	tokenValue := mintToken(t, []byte("secret-key"), "issuer", now, time.Minute)
	validator, err := New(Config{
		SigningKey: []byte("secret-key"),
		Issuer:     "issuer",
		Clock:      fixedClock{current: now},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	router := gin.New()
	router.Use(validator.GinMiddleware("claims"))
	router.GET("/protected", func(contextGin *gin.Context) {
		value, exists := contextGin.Get("claims")
		if !exists {
			t.Fatalf("claims missing")
		}
		if _, ok := value.(*Claims); !ok {
			t.Fatalf("unexpected claims type: %T", value)
		}
		contextGin.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: tokenValue})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	requestMissing := httptest.NewRequest(http.MethodGet, "/protected", nil)
	responseMissing := httptest.NewRecorder()
	router.ServeHTTP(responseMissing, requestMissing)
	if responseMissing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing cookie, got %d", responseMissing.Code)
	}
}
