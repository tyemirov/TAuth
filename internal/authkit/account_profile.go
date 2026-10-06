package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const accountProfilePath = "/auth/account"
const accountDisplayNameLimit = 200

// AccountDisplayName contains a validated account display name.
type AccountDisplayName struct{ value string }

// NewAccountDisplayName validates an explicit account display name.
func NewAccountDisplayName(raw string) (AccountDisplayName, error) {
	name := strings.TrimSpace(raw)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > accountDisplayNameLimit || strings.ContainsFunc(raw, unicode.IsControl) {
		return AccountDisplayName{}, errors.New("account.invalid_display_name")
	}
	return AccountDisplayName{value: name}, nil
}

func mountAccountProfileRoute(group *gin.RouterGroup, registry TenantRegistry, accounts AccountManagementStore, users UserStore) {
	group.PATCH("", func(request *gin.Context) {
		request.Header("Cache-Control", "no-store")
		tenantID, _, accountID, store, ok := currentAccountContext(request, registry, accounts)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			request.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{"error": "unsupported_media_type"})
			return
		}
		var inbound struct {
			DisplayName *string `json:"display_name"`
		}
		decoder := json.NewDecoder(request.Request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inbound); err != nil {
			request.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			request.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
			return
		}
		rawName := ""
		if inbound.DisplayName != nil {
			rawName = *inbound.DisplayName
		}
		name, err := NewAccountDisplayName(rawName)
		if err != nil {
			request.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid_display_name"})
			return
		}
		profile, err := store.CorrectAccountDisplayName(request.Request.Context(), tenantID, accountID, name, users)
		if err != nil {
			writeAccountError(request, err)
			return
		}
		request.JSON(http.StatusOK, accountProfilePayload(profile))
	})
}

// CorrectAccountDisplayName persists an explicit display-name override for a tenant account.
func (store *MemoryPasswordCredentialStore) CorrectAccountDisplayName(ctx context.Context, tenantID, accountID string, name AccountDisplayName, users UserStore) (AccountProfile, error) {
	if err := ctx.Err(); err != nil {
		return AccountProfile{}, fmt.Errorf("account.profile_update: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account := store.accounts[tenantID][accountID]
	if account == nil {
		return AccountProfile{}, ErrAccountNotFound
	}
	if account.state != accountStateActive {
		return AccountProfile{}, ErrAccountNotActive
	}
	if _, _, err := users.UpsertAccountUser(ctx, tenantID, accountID, account.userEmail, name.value, account.avatarURL); err != nil {
		return AccountProfile{}, fmt.Errorf("account.profile_update.user: %w", err)
	}
	account.displayName = name.value
	account.displayNameOverride = true
	return profileFromAccount(account), nil
}

// CorrectAccountDisplayName persists an account override and its user profile atomically.
func (store *DatabaseUserStore) CorrectAccountDisplayName(ctx context.Context, tenantID, accountID string, name AccountDisplayName, users UserStore) (AccountProfile, error) {
	if users != store {
		return AccountProfile{}, errors.New("account.profile_update.unsupported_user_store")
	}
	var profile AccountProfile
	err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := store.now().UTC().Unix()
		result := tx.Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStateActive).
			Updates(map[string]interface{}{"user_display_name": name.value, "display_name_override": name.value, "last_updated_unix": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrAccountNotActive
		}
		var err error
		profile, err = store.accountProfileWithTx(ctx, tx, tenantID, accountID)
		if err != nil {
			return err
		}
		userProfile := userProfileRecord{TenantID: tenantID, UserID: profile.UserID, UserEmail: profile.UserEmail, UserDisplayName: profile.DisplayName, UserAvatarURL: profile.AvatarURL, UserRoles: roleList(profile.Roles), CreatedAtUnix: now, LastUpdatedUnix: now}
		err = tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}}, DoUpdates: clause.AssignmentColumns([]string{"user_display_name", "last_updated_unix"})}).Create(&userProfile).Error

		return err
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("account.profile_update: %w", err)
	}
	return profile, nil
}
