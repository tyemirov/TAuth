package authkit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	accountStateErasing         = "erasing"
	AccountErasureStatusPath    = "/auth/account-erasure"
	erasurePending              = "pending"
	erasureRunning              = "running"
	erasureBlocked              = "blocked"
	erasureCompleted            = "completed"
	erasureProviderPhase        = "provider_revocation"
	erasureOAuthPhase           = "oauth_purge"
	erasureRefreshPhase         = "refresh_purge"
	erasureUserPhase            = "user_purge"
	erasureProviderUnavailable  = "provider_revocation_unavailable"
	erasureProviderFailed       = "provider_revocation_failed"
	erasureOAuthFailed          = "oauth_purge_failed"
	erasureRefreshFailed        = "refresh_purge_failed"
	erasureUserFailed           = "user_purge_failed"
	erasureConfiguredCredential = "configured_credential"
	erasureReceiptTTL           = 30 * 24 * time.Hour
	erasureLeaseTTL             = time.Minute
	erasurePhaseTimeout         = 15 * time.Second
	erasureScanInterval         = 30 * time.Second
	erasureBatchSize            = 25
)

var (
	errErasureKeyInvalid  = errors.New("account.erasure.invalid_status_key")
	errErasureKeyConflict = errors.New("account.erasure.status_key_conflict")
	errErasureNotFound    = errors.New("account.erasure.not_found")
	errErasureLeaseLost   = errors.New("account.erasure.lease_lost")
	errErasureConfigured  = errors.New("account.erasure.configured_credential")
)

// UserDataPurger removes persisted user data for one tenant and subject.
type UserDataPurger interface {
	PurgeUser(context.Context, string, string) error
}

type erasureDatabasePurger interface {
	UserDataPurger
	ErasureDatabaseIdentity() string
}

// AccountProviderRevoker removes reusable provider grants before credential deletion.
// Implementations must support cancellation and idempotent retries.
type AccountProviderRevoker interface {
	RevokeAccountProvider(context.Context, string, string, string) error
}

// AccountErasureCoordinator executes durable, fenced account erasure phases.
type AccountErasureCoordinator struct {
	accounts *DatabaseUserStore
	refresh  UserDataPurger
	oauth    UserDataPurger
	provider AccountProviderRevoker
}

// NewAccountErasureCoordinator requires an account store with its own canonical user profiles.
func NewAccountErasureCoordinator(accounts *DatabaseUserStore, users UserStore, refresh RefreshTokenStore, oauth OAuthGrantRevoker, provider AccountProviderRevoker) (*AccountErasureCoordinator, error) {
	if accounts == nil || users != accounts {
		return nil, errors.New("account.erasure.unsupported_user_store")
	}
	refreshPurger, ok := refresh.(erasureDatabasePurger)
	if !ok || refreshPurger.ErasureDatabaseIdentity() != accounts.databaseIdentity {
		return nil, errors.New("account.erasure.refresh_purge_unavailable")
	}
	var oauthPurger UserDataPurger
	if oauth != nil {
		var ok bool
		oauthPurger, ok = oauth.(erasureDatabasePurger)
		if !ok || oauth.(erasureDatabasePurger).ErasureDatabaseIdentity() != accounts.databaseIdentity {
			return nil, errors.New("account.erasure.oauth_purge_unavailable")
		}
	}
	return &AccountErasureCoordinator{accounts: accounts, refresh: refreshPurger, oauth: oauthPurger, provider: provider}, nil
}

func validateErasureStatusKey(key string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != key {
		return "", errErasureKeyInvalid
	}
	return hashOpaque(key), nil
}

func erasureRepresentation(job databaseAccountErasure) gin.H {
	var expires any
	if job.ExpiresUnix != 0 {
		expires = time.Unix(job.ExpiresUnix, 0).UTC()
	}
	return gin.H{"operation_id": job.OperationID, "state": job.State, "reason": job.Reason, "created_at": time.Unix(job.CreatedUnix, 0).UTC(), "updated_at": time.Unix(job.UpdatedUnix, 0).UTC(), "expires_at": expires}
}

func mountAccountErasureRoutes(router gin.IRouter, registry TenantRegistry, users UserStore, accountStore AccountManagementStore, refresh RefreshTokenStore, oauth OAuthGrantRevoker) {
	accounts, _ := accountStore.(*DatabaseUserStore)
	provider, _ := oauth.(AccountProviderRevoker)
	coordinator, coordinatorErr := NewAccountErasureCoordinator(accounts, users, refresh, oauth, provider)
	tenant := func(request *gin.Context) (string, bool) {
		id, ok := resolveTenantIDRequired(request, registry)
		if !ok {
			request.AbortWithStatus(http.StatusInternalServerError)
		}
		return id, ok
	}
	router.GET(AccountErasureStatusPath, func(request *gin.Context) {
		request.Header("Cache-Control", "no-store")
		tenantID, ok := tenant(request)
		if !ok {
			return
		}
		if coordinatorErr != nil {
			request.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "account_erasure_unavailable"})
			return
		}
		authorization := request.GetHeader("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			request.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		keyHash, err := validateErasureStatusKey(strings.TrimPrefix(authorization, "Bearer "))
		if err != nil {
			request.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_status_key"})
			return
		}
		job, err := accounts.erasureByKey(request.Request.Context(), tenantID, keyHash)
		if errors.Is(err, errErasureNotFound) {
			request.AbortWithStatus(http.StatusNotFound)
			return
		}
		if err != nil {
			logAuthError("auth.account.erasure_status", err)
			request.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		request.JSON(http.StatusOK, erasureRepresentation(job))
	})
	router.DELETE(accountProfilePath, func(request *gin.Context) {
		request.Header("Cache-Control", "no-store")
		tenantID, ok := tenant(request)
		if !ok {
			return
		}
		if coordinatorErr != nil {
			request.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "account_erasure_unavailable"})
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			request.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{"error": "unsupported_media_type"})
			return
		}
		var inbound struct {
			StatusKey string `json:"status_key"`
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
		keyHash, err := validateErasureStatusKey(inbound.StatusKey)
		if err != nil {
			request.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid_status_key"})
			return
		}
		job, lookupErr := accounts.erasureByKey(request.Request.Context(), tenantID, keyHash)
		if errors.Is(lookupErr, errErasureNotFound) {
			claims, err := validateSessionRequest(request.Request, registry.Config(tenantID))
			if err != nil || claims.GetTenantID() != tenantID {
				request.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			config := registry.Config(tenantID)
			if !config.AccountManagementEnabled {
				request.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": errorAccountManagementNotConfigured})
				return
			}
			job, err = accounts.beginAccountErasure(request.Request.Context(), tenantID, claims.GetUserID(), keyHash)
			if errors.Is(err, errErasureKeyConflict) || errors.Is(err, errErasureConfigured) {
				reason := "status_key_conflict"
				if errors.Is(err, errErasureConfigured) {
					reason = erasureConfiguredCredential
				}
				request.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": reason})
				return
			}
			if err != nil {
				writeAccountError(request, err)
				return
			}
		} else if lookupErr != nil {
			logAuthError("auth.account.erasure_lookup", lookupErr)
			request.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if err := coordinator.Process(request.Request.Context(), job.OperationID); err != nil {
			logAuthError("auth.account.erasure_process", err)
		}
		job, err = accounts.erasureByKey(request.Request.Context(), tenantID, keyHash)
		if err != nil {
			logAuthError("auth.account.erasure_result", err)
			request.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		request.Header("Location", AccountErasureStatusPath)
		request.JSON(http.StatusAccepted, erasureRepresentation(job))
	})
}

// Process executes due phases for one operation under a renewable fenced lease.
func (coordinator *AccountErasureCoordinator) Process(ctx context.Context, operationID string) error {
	job, claimed, err := coordinator.accounts.claimErasure(ctx, operationID)
	if err != nil || !claimed {
		return err
	}
	if job.UserID == nil {
		return errors.New("account.erasure.application_subject_missing")
	}
	for {
		phaseCtx, cancel := context.WithTimeout(ctx, erasurePhaseTimeout)
		reason := ""
		switch job.Phase {
		case erasureProviderPhase:
			providers, providerErr := coordinator.accounts.requiredErasureProviders(phaseCtx, job)
			err = providerErr
			for _, provider := range providers {
				if err != nil {
					break
				}
				if coordinator.provider == nil {
					reason = erasureProviderUnavailable
					err = errors.New("account.erasure.provider_revoker_unavailable")
					break
				}
				err = coordinator.provider.RevokeAccountProvider(phaseCtx, job.TenantID, *job.AccountID, provider)
			}
			if reason == "" {
				reason = erasureProviderFailed
			}
		case erasureOAuthPhase:
			if coordinator.oauth != nil {
				err = coordinator.oauth.PurgeUser(phaseCtx, job.TenantID, *job.UserID)
			} else {
				err = nil
			}
			reason = erasureOAuthFailed
		case erasureRefreshPhase:
			err = coordinator.refresh.PurgeUser(phaseCtx, job.TenantID, *job.UserID)
			reason = erasureRefreshFailed
		case erasureUserPhase:
			err = coordinator.accounts.completeAccountErasure(phaseCtx, job)
			reason = erasureUserFailed
		default:
			err = fmt.Errorf("account.erasure.invalid_phase: %s", job.Phase)
			reason = erasureUserFailed
		}
		cancel()
		if err != nil {
			failure := fmt.Errorf("account.erasure.%s operation=%s: %w", job.Phase, job.OperationID, err)
			persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second*2)
			persistErr := coordinator.accounts.blockErasure(persistCtx, job, reason)
			persistCancel()
			return errors.Join(failure, persistErr)
		}
		if job.Phase == erasureUserPhase {
			return nil
		}
		next := map[string]string{erasureProviderPhase: erasureOAuthPhase, erasureOAuthPhase: erasureRefreshPhase, erasureRefreshPhase: erasureUserPhase}[job.Phase]
		if err := coordinator.accounts.advanceErasure(ctx, job, next); err != nil {
			return err
		}
		job.Phase = next
	}
}

// Resume processes a bounded due batch and removes expired completion receipts.
func (coordinator *AccountErasureCoordinator) Resume(ctx context.Context) error {
	if err := coordinator.accounts.cleanupErasureReceipts(ctx); err != nil {
		return err
	}
	now := coordinator.accounts.now().UTC().Unix()
	var jobs []databaseAccountErasure
	err := coordinator.accounts.db.WithContext(ctx).Where("state <> ? AND next_attempt_unix <= ? AND lease_until_unix <= ?", erasureCompleted, now, now).Order("next_attempt_unix, created_unix").Limit(erasureBatchSize).Find(&jobs).Error
	if err != nil {
		return fmt.Errorf("account.erasure.resume_lookup: %w", err)
	}
	var failures []error
	for _, job := range jobs {
		if err := coordinator.Process(ctx, job.OperationID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Run resumes due jobs at a bounded interval until the server context ends.
func (coordinator *AccountErasureCoordinator) Run(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(erasureScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := coordinator.Resume(ctx); err != nil {
				report(err)
			}
		}
	}
}

func lockActiveAccount(ctx context.Context, tx *gorm.DB, tenantID, accountID string) error {
	result := tx.WithContext(ctx).Model(&databaseAccountRecord{}).Where("tenant_id = ? AND account_id = ? AND account_state = ?", tenantID, accountID, accountStateActive).Update("last_updated_unix", gorm.Expr("last_updated_unix"))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAccountNotActive
	}
	return nil
}

// RequireActiveAccountWrite reserves the canonical public subject for an atomic dependent write.
func RequireActiveAccountWrite(ctx context.Context, tx *gorm.DB, tenantID, userID string) error {
	result := tx.WithContext(ctx).Model(&databaseAccountRecord{}).Where("tenant_id = ? AND user_id = ? AND account_state = ?", tenantID, userID, accountStateActive).Update("last_updated_unix", gorm.Expr("last_updated_unix"))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAccountNotActive
	}
	return nil
}

// ErasureDatabaseIdentity hashes the exact selected database URL for adapter ownership checks.
func ErasureDatabaseIdentity(databaseURL string) string { return hashOpaque(databaseURL) }
