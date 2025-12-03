package sessionvalidator

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSystemClockNowReturnsUTCTime(t *testing.T) {
	clock := systemClock{}
	now := clock.Now()
	if now.Location() != time.UTC {
		t.Fatalf("expected UTC time, got %s", now.Location())
	}
}

func TestClaimsGetterFallbacks(t *testing.T) {
	var nilClaims *Claims
	if nilClaims.GetUserID() != "" || nilClaims.GetTenantID() != "" || nilClaims.GetUserEmail() != "" {
		t.Fatalf("expected empty getters on nil claims")
	}
	if nilClaims.GetUserDisplayName() != "" || nilClaims.GetUserAvatarURL() != "" {
		t.Fatalf("expected empty display/avatar on nil claims")
	}
	if nilClaims.GetUserRoles() != nil {
		t.Fatalf("expected nil roles slice on nil claims")
	}
	if !nilClaims.GetExpiresAt().IsZero() {
		t.Fatalf("expected zero expires at on nil claims")
	}

	expires := time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)
	claims := &Claims{
		TenantID:        "tenant",
		UserID:          "user",
		UserEmail:       "user@example.com",
		UserDisplayName: "User Name",
		UserAvatarURL:   "https://example.com/avatar.png",
		UserRoles:       []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}

	if claims.GetUserID() != "user" ||
		claims.GetTenantID() != "tenant" ||
		claims.GetUserEmail() != "user@example.com" {
		t.Fatalf("unexpected basic getters")
	}
	if claims.GetUserDisplayName() != "User Name" || claims.GetUserAvatarURL() != "https://example.com/avatar.png" {
		t.Fatalf("unexpected user display or avatar")
	}
	if roles := claims.GetUserRoles(); len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("unexpected roles: %#v", roles)
	}
	if !claims.GetExpiresAt().Equal(expires) {
		t.Fatalf("unexpected expires: %v", claims.GetExpiresAt())
	}
}
