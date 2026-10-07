package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AppleNotificationPath accepts authenticated Apple server notifications.
const AppleNotificationPath = "/auth/apple/notifications"

type appleNotification struct {
	ID, Audience, Subject, EventType string
	IssuedUnix, EventUnix            int64
}

func mountAppleNotifications(router gin.IRouter, registry TenantRegistry, accounts *DatabaseUserStore) {
	router.POST(AppleNotificationPath, func(request *gin.Context) {
		request.Header("Cache-Control", "no-store")
		var inbound struct {
			Payload string `json:"payload"`
		}
		decoder := json.NewDecoder(request.Request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inbound); err != nil {
			request.AbortWithStatus(http.StatusBadRequest)
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			request.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if accounts == nil || accounts.providerGrantCipher == nil {
			request.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		if len(inbound.Payload) == 0 || len(inbound.Payload) > 65536 {
			request.AbortWithStatus(http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(inbound.Payload, claims); err != nil {
			request.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		audiences, err := claims.GetAudience()
		if err != nil || len(audiences) != 1 {
			request.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var config ServerConfig
		matches := 0
		for _, candidate := range registry.configs {
			if candidate.AppleOAuth.Enabled && candidate.AppleOAuth.NotificationAudience != "" && candidate.AppleOAuth.NotificationAudience == audiences[0] {
				config = candidate
				matches++
			}
		}
		if matches != 1 {
			request.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		event, err := verifyAppleNotification(request.Request.Context(), config.AppleOAuth, inbound.Payload, accounts.now().UTC())
		if err != nil {
			request.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if err := accounts.applyAppleNotification(request.Request.Context(), config.TenantID, event); err != nil {
			logAuthError("auth.apple.notification", err)
			request.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		request.Status(http.StatusNoContent)
	})
}

func verifyAppleNotification(ctx context.Context, config AppleOAuthConfig, payload string, now time.Time) (appleNotification, error) {
	keys, err := fetchAppleJWKS(ctx, resolveAppleOAuthHTTPClient(), config.JWKSURL)
	if err != nil {
		return appleNotification{}, err
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(payload, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errAppleOAuthIDToken
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errAppleOAuthIDToken
		}
		return keys.publicKey(kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(appleIssuer), jwt.WithAudience(config.NotificationAudience), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }), jwt.WithLeeway(5*time.Minute))
	if err != nil {
		return appleNotification{}, err
	}
	audience, err := claims.GetAudience()
	if err != nil || len(audience) != 1 || audience[0] != config.NotificationAudience {
		return appleNotification{}, errAppleOAuthIDToken
	}
	issued, err := claims.GetIssuedAt()
	if err != nil || issued == nil || issued.Unix() <= 0 || issued.Unix() > now.Add(5*time.Minute).Unix() {
		return appleNotification{}, errAppleOAuthIDToken
	}
	id := readStringMapClaim(claims, "jti")
	if id == "" || len(id) > 200 {
		return appleNotification{}, errAppleOAuthIDToken
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		return appleNotification{}, errAppleOAuthIDToken
	}
	subject := readStringMapClaim(events, "sub")
	kind := readStringMapClaim(events, "type")
	eventFloat, ok := events["event_time"].(float64)
	eventUnix := int64(eventFloat)
	if !ok || eventUnix <= 0 || float64(eventUnix) != eventFloat || eventUnix > issued.Add(5*time.Minute).Unix() || eventUnix > now.Add(5*time.Minute).Unix() || subject == "" || len(subject) > 512 {
		return appleNotification{}, errAppleOAuthIDToken
	}
	switch kind {
	case "consent-revoked", "account-deleted", "email-enabled", "email-disabled":
	default:
		return appleNotification{}, errAppleOAuthIDToken
	}
	return appleNotification{id, audience[0], subject, kind, issued.Unix(), eventUnix}, nil
}

func (store *DatabaseUserStore) applyAppleNotification(ctx context.Context, tenant string, event appleNotification) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The receipt insert reserves the database writer before operation reads.
		receipt := databaseAppleEventReceipt{TenantID: tenant, EventID: event.ID, ReceivedUnix: store.now().UTC().Unix(), Outcome: "processed"}
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&receipt)
		if inserted.Error != nil {
			return inserted.Error
		}
		if inserted.RowsAffected == 0 {
			return nil
		}
		if event.EventType != "consent-revoked" && event.EventType != "account-deleted" {
			return nil
		}
		var obligations []databaseErasureProvider
		if err := tx.Where("tenant_id = ? AND provider = ? AND state <> ? AND operation_id IN (SELECT operation_id FROM apple_erasure_subjects WHERE tenant_id = ? AND subject_hash = ?)", tenant, accountProviderApple, providerRevoked, tenant, hashOpaque(event.Subject)).Find(&obligations).Error; err != nil {
			return err
		}
		for _, obligation := range obligations {
			var operation databaseAccountErasure
			if err := tx.Where("operation_id = ? AND tenant_id = ?", obligation.OperationID, tenant).Take(&operation).Error; err != nil {
				return err
			}
			clear, err := store.providerGrantCipher.OpenProviderGrant(appleErasureBinding(tenant, operation.OperationID), obligation.Ciphertext)
			if err != nil {
				return err
			}
			var snapshot appleErasureSnapshot
			if err := json.Unmarshal(clear, &snapshot); err != nil {
				return err
			}
			if len(snapshot.Grants) == 0 {
				return errors.New("account.erasure.empty_apple_snapshot")
			}
			if snapshot.NotificationAudience == "" || snapshot.NotificationAudience != event.Audience || event.EventUnix <= operation.CreatedUnix || event.IssuedUnix < operation.CreatedUnix {
				if snapshot.NotificationAudience == event.Audience {
					if err := tx.Model(&databaseAppleEventReceipt{}).Where("tenant_id = ? AND event_id = ?", tenant, event.ID).Update("outcome", "event_generation_ambiguous").Error; err != nil {
						return err
					}
				}
				continue
			}
			matched := false
			remaining := false
			for index, grant := range snapshot.Grants {
				if grant.Subject == event.Subject && event.EventUnix > grant.IssuedUnix && event.IssuedUnix >= grant.IssuedUnix {
					snapshot.Grants[index].Revoked = true
					snapshot.Grants[index].RefreshToken = ""
					matched = true
				}
				if !snapshot.Grants[index].Revoked {
					remaining = true
				}
			}
			if !matched {
				continue
			}
			updates := map[string]any{"state": providerRevoked, "ciphertext": nil, "subject_hash": ""}
			if remaining {
				encoded, err := json.Marshal(snapshot)
				if err != nil {
					return err
				}
				ciphertext, err := store.providerGrantCipher.SealProviderGrant(appleErasureBinding(tenant, operation.OperationID), encoded)
				if err != nil {
					return err
				}
				updates = map[string]any{"ciphertext": ciphertext}
			}
			if err := tx.Model(&databaseErasureProvider{}).Where("operation_id = ? AND provider = ?", operation.OperationID, accountProviderApple).Updates(updates).Error; err != nil {
				return err
			}

			now := store.now().UTC().Unix()
			if operation.AccountState == erasureAccountRemoved {
				changed := tx.Model(&databaseAccountErasure{}).Where("operation_id = ? AND NOT EXISTS (SELECT 1 FROM account_erasure_providers WHERE operation_id = ? AND state <> ?)", operation.OperationID, operation.OperationID, providerRevoked).Updates(map[string]any{"state": erasureCompleted, "reason": "", "phase": "", "lease_token": "", "lease_until_unix": 0, "next_attempt_unix": 0, "attempt_count": 0, "updated_unix": now, "expires_unix": now + int64(erasureReceiptTTL.Seconds())})
				if changed.Error != nil {
					return changed.Error
				}
			}
		}
		return nil
	})
}
