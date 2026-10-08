package authkit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSecurityChallengeResponsesContainNoSecret(t *testing.T) {
	config := newTestServerConfig()
	config.PasswordAuthEnabled = true
	config.AccountManagementEnabled = true
	config.EmailDeliveryEnabled = true
	config.PasswordResetURL = "https://app.example/reset"
	accounts := NewMemoryPasswordCredentialStore()
	signup, err := accounts.CreatePasswordSignup(context.Background(), config.TenantID, AccountPasswordRequest{UserEmail: "known@example.com", Password: "correct horse battery staple"}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.VerifyEmailChallenge(context.Background(), config.TenantID, signup.Token); err != nil {
		t.Fatal(err)
	}
	sender := &recordingEmailChallengeSender{}
	router := gin.New()
	MountAuthRoutesWithPassword(router, NewSingleTenantRegistry(config), newTestUserStore(), NewMemoryRefreshTokenStore(), nil, accounts, newTestPasswordResetDispatcher(t), sender, nil)
	server := httptest.NewServer(router)
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/auth/password/reset/start", "application/json", strings.NewReader(`{"email":"known@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, present := body["reset_token"]; present {
		t.Fatal("public reset response contains a usable secret")
	}
	sender.WaitRequests(t, 1)
	if response.StatusCode != http.StatusAccepted || len(sender.Snapshot()) != 1 {
		t.Fatalf("reset delivery failed: status=%d deliveries=%d", response.StatusCode, len(sender.Snapshot()))
	}
	token := challengeTokenFromDeliveryURL(t, sender.Snapshot()[0], EmailChallengeKindPasswordReset)
	completed, err := server.Client().Post(server.URL+"/auth/password/reset/complete", "application/json", strings.NewReader(`{"token":"`+token+`","password":"replacement correct horse battery staple"}`))
	if err != nil {
		t.Fatal(err)
	}
	completed.Body.Close()
	if completed.StatusCode != http.StatusOK {
		t.Fatalf("email token rejected: %d", completed.StatusCode)
	}
}

func enableTestChallengeDelivery(config *ServerConfig) *recordingEmailChallengeSender {
	config.EmailDeliveryEnabled = true
	config.EmailVerificationURL = "https://app.example/verify"
	config.PasswordResetURL = "https://app.example/reset"
	config.PasswordLinkURL = "https://app.example/link"
	return &recordingEmailChallengeSender{}
}
