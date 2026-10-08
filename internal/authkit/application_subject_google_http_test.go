package authkit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/api/idtoken"
	"gorm.io/gorm"
)

func TestApplicationSubjectGoogleHTTP(t *testing.T) {
	for _, migrated := range []bool{false, true} {
		label := "fresh"
		if migrated {
			label = "migrated"
		}
		t.Run(label, func(t *testing.T) {
			config := newMobileNativeTestServerConfig()
			databaseURL := sqliteDatabaseURL(t)
			if migrated {
				db, err := OpenControlDatabase(context.Background(), databaseURL, &userProfileRecord{})
				if err != nil {
					t.Fatal(err)
				}
				old := userProfileRecord{TenantID: config.TenantID, UserID: "google:stable", UserEmail: "original@example.com", UserDisplayName: "Parent", UserRoles: roleList{"parent"}}
				if err = db.Create(&old).Error; err != nil {
					t.Fatal(err)
				}
				if err = db.Transaction(func(tx *gorm.DB) error { return MigrateApplicationSubjects(context.Background(), tx) }); err != nil {
					t.Fatal(err)
				}
				raw, _ := db.DB()
				if err = raw.Close(); err != nil {
					t.Fatal(err)
				}
			}
			users, err := NewDatabaseUserStore(context.Background(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			refresh, err := NewDatabaseRefreshTokenStore(context.Background(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			registry := NewSingleTenantRegistry(config)
			validator := &fakeGoogleValidator{results: map[string]validatorResult{}}
			ProvideGoogleTokenValidator(validator)
			t.Cleanup(func() { ProvideGoogleTokenValidator(nil) })
			router := gin.New()
			MountAuthRoutesWithPassword(router, registry, users, refresh, nil, users, newTestPasswordResetDispatcher(t), nil, nil)
			server := httptest.NewTLSServer(router)
			t.Cleanup(server.Close)
			client := server.Client()
			client.Jar, _ = cookiejar.New(nil)
			read := func(method, path, body string) (int, map[string]any) {
				request, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				if method != http.MethodGet {
					request.Header.Set("Content-Type", "application/json")
				}
				response, e := client.Do(request)
				if e != nil {
					t.Fatal(e)
				}
				defer response.Body.Close()
				payload, e := io.ReadAll(response.Body)
				if e != nil {
					t.Fatal(e)
				}
				var result map[string]any
				if len(payload) > 0 {
					if e = json.Unmarshal(payload, &result); e != nil {
						t.Fatalf("payload=%s err=%v", payload, e)
					}
				}
				return response.StatusCode, result
			}
			login := func(subject, email, platform string) string {
				audience := "android-client-id"
				redirect := "com.promptdew.mobile:/oauth2redirect/google"
				if platform == "ios" {
					audience = "ios-client-id"
					redirect = "com.promptdew.mobile://oauth2redirect/google"
				}
				status, noncePayload := read(http.MethodPost, "/auth/nonce", `{}`)
				if status != http.StatusOK {
					t.Fatalf("nonce=%d %v", status, noncePayload)
				}
				nonce := noncePayload["nonce"].(string)
				validator.results["identity"] = validatorResult{payload: &idtoken.Payload{Claims: map[string]interface{}{"iss": googleIssuerHTTPS, "sub": subject, "email": email, "email_verified": true, "name": "Parent", "nonce": nonce}}, expectedAudience: audience}
				encoded, _ := json.Marshal(map[string]string{"google_id_token": "identity", "nonce_token": nonce, "platform": platform, "redirect_uri": redirect})
				status, payload := read(http.MethodPost, "/auth/google/native", string(encoded))
				if status != http.StatusOK {
					t.Fatalf("login=%d %v", status, payload)
				}
				return payload["user_id"].(string)
			}
			browserLogin := func(subject, email string) string {
				status, noncePayload := read(http.MethodPost, "/auth/nonce", `{}`)
				if status != http.StatusOK {
					t.Fatalf("nonce=%d %v", status, noncePayload)
				}
				nonce := noncePayload["nonce"].(string)
				validator.results["browser"] = validatorResult{payload: &idtoken.Payload{Claims: map[string]interface{}{"iss": googleIssuerHTTPS, "sub": subject, "email": email, "email_verified": true, "name": "Parent", "nonce": nonce}}, expectedAudience: config.GoogleWebClientID}
				encoded, _ := json.Marshal(map[string]string{"google_id_token": "browser", "nonce_token": nonce})
				status, payload := read(http.MethodPost, "/auth/google", string(encoded))
				if status != http.StatusOK {
					t.Fatalf("browser login=%d %v", status, payload)
				}
				return payload["user_id"].(string)
			}
			original := login("stable", "original@example.com", "android")
			if migrated && original != "google:stable" {
				t.Fatalf("changed migrated subject: %s", original)
			}
			if !migrated {
				assertOpaqueAccountID(t, original)
			}
			account, err := users.ResolveAccountForUser(context.Background(), config.TenantID, original)
			if err != nil {
				t.Fatal(err)
			}
			internalID := account.AccountID
			assertOpaqueAccountID(t, internalID)
			for _, enabled := range []bool{true, false, true} {
				next := registry.configs[config.TenantID]
				next.AccountManagementEnabled = enabled
				registry.configs[config.TenantID] = next
				for _, path := range []string{"/auth/session", "/me"} {
					status, payload := read(http.MethodGet, path, "")
					if status != http.StatusOK || payload["user_id"] != original {
						t.Fatalf("toggle=%v path=%s status=%d payload=%v", enabled, path, status, payload)
					}
				}
				if status, payload := read(http.MethodPost, "/auth/refresh", `{}`); status != http.StatusNoContent {
					t.Fatalf("refresh=%d %v", status, payload)
				}
				if current := login("stable", "changed@example.com", "ios"); current != original {
					t.Fatalf("email/toggle changed identity: %s", current)
				}
				if current := browserLogin("stable", "changed@example.com"); current != original {
					t.Fatalf("browser changed identity: %s", current)
				}
				account, err = users.ResolveAccountForUser(context.Background(), config.TenantID, original)
				if err != nil || account.AccountID != internalID || account.UserEmail != "changed@example.com" {
					t.Fatalf("account=%+v err=%v", account, err)
				}
			}
			if other := login("different", "changed@example.com", "android"); other == original {
				t.Fatal("different provider subjects merged by email")
			}
			if current := login("stable", "changed@example.com", "android"); current != original {
				t.Fatal("original identity changed")
			}
			status, payload := read(http.MethodPatch, "/auth/account", `{"display_name":"Corrected Parent"}`)
			if status != http.StatusOK || payload["user_id"] != original {
				t.Fatalf("correction=%d %v", status, payload)
			}
			if current := login("stable", "changed@example.com", "android"); current != original {
				t.Fatal("correction changed subject")
			}
			if status, payload = read(http.MethodGet, "/auth/session", ""); status != http.StatusOK || payload["display"] != "Corrected Parent" {
				t.Fatalf("override lost: %d %v", status, payload)
			}
			raw, _ := users.db.DB()
			if err = raw.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewDatabaseUserStore(context.Background(), databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			account, err = reopened.ResolveAccountForUser(context.Background(), config.TenantID, original)
			if err != nil || account.AccountID != internalID || account.DisplayName != "Corrected Parent" {
				t.Fatalf("restart=%+v %v", account, err)
			}
			var count int64
			if err = reopened.db.Model(&databaseAccountIdentityRecord{}).Where("tenant_id = ? AND provider = ? AND provider_id = ?", config.TenantID, "google", "stable").Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("duplicate identity=%d %v", count, err)
			}
			router = gin.New()
			MountAuthRoutesWithPassword(router, registry, reopened, refresh, nil, reopened, newTestPasswordResetDispatcher(t), nil, nil)
			server.Config.Handler = router
			if status, payload = read(http.MethodGet, "/auth/session", ""); status != http.StatusOK || payload["user_id"] != original {
				t.Fatalf("restarted session=%d %v", status, payload)
			}
			if status, payload = read(http.MethodPost, "/auth/account/disable", `{}`); status != http.StatusNoContent {
				t.Fatalf("disable=%d %v", status, payload)
			}
			for _, enabled := range []bool{false, true} {
				next := registry.configs[config.TenantID]
				next.AccountManagementEnabled = enabled
				registry.configs[config.TenantID] = next
				if status, payload = read(http.MethodGet, "/me", ""); status != http.StatusForbidden && status != http.StatusUnauthorized {
					t.Fatalf("disabled flag=%v session=%d %v", enabled, status, payload)
				}
			}
			if _, err = reopened.ReactivateAccount(context.Background(), config.TenantID, internalID); err != nil {
				t.Fatal(err)
			}
			users = reopened
			if current := login("stable", "changed@example.com", "android"); current != original {
				t.Fatal("reactivation changed subject")
			}
			key := newErasureStatusKey(t)
			status, payload = read(http.MethodDelete, "/auth/account", `{"status_key":"`+key+`"}`)
			if status != http.StatusAccepted || payload["state"] != erasureCompleted {
				t.Fatalf("erasure=%d %v", status, payload)
			}
			if _, err = reopened.ResolveAccountForUser(context.Background(), config.TenantID, original); err == nil {
				t.Fatal("erasure retained public mapping")
			}
			if current := login("stable", "changed@example.com", "android"); current == original {
				t.Fatal("erased account recreated former subject")
			}

		})
	}
}
