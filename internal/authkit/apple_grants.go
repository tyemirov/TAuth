package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	providerPending        = "pending"
	providerManual         = "manual_action_required"
	providerRevoked        = "revoked"
	erasureAccountRetained = "retained"
	erasureAccountRemoved  = "removed"
	appleManualReason      = "apple_revocation_manual_action_required"
	appleRevokeEndpoint    = "https://appleid.apple.com/auth/revoke"
)

// ProviderGrantCipher protects provider grants with the canonical server encryption key.
type ProviderGrantCipher interface {
	SealProviderGrant(string, []byte) ([]byte, error)
	OpenProviderGrant(string, []byte) ([]byte, error)
}

// SetProviderGrantCipher selects the immutable cipher before the store serves requests.
func (store *DatabaseUserStore) SetProviderGrantCipher(cipher ProviderGrantCipher) {
	store.providerGrantCipher = cipher
}

type databaseAppleGrant struct {
	TenantID    string `gorm:"primaryKey"`
	AccountID   string `gorm:"primaryKey"`
	Audience    string `gorm:"primaryKey"`
	SubjectHash string `gorm:"primaryKey"`
	Ciphertext  []byte `gorm:"not null"`
}

func (databaseAppleGrant) TableName() string { return "apple_grants" }

type appleGrant struct {
	Subject      string `json:"subject"`
	Audience     string `json:"audience"`
	RefreshToken string `json:"refresh_token"`
	IssuedUnix   int64  `json:"issued_unix"`
	Revoked      bool   `json:"revoked"`
}

type databaseErasureProvider struct {
	OperationID string `gorm:"primaryKey"`
	Provider    string `gorm:"primaryKey"`
	TenantID    string `gorm:"index;not null"`
	SubjectHash string `gorm:"index;not null"`
	State       string `gorm:"not null"`
	Ciphertext  []byte
}

func (databaseErasureProvider) TableName() string { return "account_erasure_providers" }

type databaseAppleEventReceipt struct {
	TenantID     string `gorm:"primaryKey"`
	EventID      string `gorm:"primaryKey"`
	ReceivedUnix int64  `gorm:"not null"`
	Outcome      string `gorm:"not null"`
}

func (databaseAppleEventReceipt) TableName() string { return "apple_event_receipts" }

func appleGrantBinding(tenant, owner, audience string) string {
	binding, _ := json.Marshal([]string{"apple_grant", tenant, owner, audience})
	return string(binding)
}
func providerErasureBinding(tenant, operation, provider string) string {
	binding, _ := json.Marshal([]string{"account_erasure", tenant, operation, provider})
	return string(binding)
}
func appleErasureBinding(tenant, operation string) string {
	return providerErasureBinding(tenant, operation, accountProviderApple)
}

type appleErasureSnapshot struct {
	NotificationAudience string       `json:"notification_audience"`
	Grants               []appleGrant `json:"grants"`
}

type githubErasureGrant struct {
	AccountID  string `json:"account_id"`
	UserID     string `json:"user_id"`
	Ciphertext []byte `json:"ciphertext"`
}

func persistAppleLoginGrant(ctx context.Context, accounts AccountManagementStore, tenant, account string, identity appleIdentity, token appleTokenResponse) error {
	store, ok := accounts.(*DatabaseUserStore)
	if !ok || store.providerGrantCipher == nil {
		return errors.New("auth.apple.grant_cipher_unavailable")
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		return errors.New("auth.apple.refresh_token_missing")
	}
	grant := appleGrant{Subject: identity.Subject, Audience: identity.Audience, RefreshToken: token.RefreshToken, IssuedUnix: store.now().UTC().Unix()}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	ciphertext, err := store.providerGrantCipher.SealProviderGrant(appleGrantBinding(tenant, account, identity.Audience), encoded)
	if err != nil {
		return err
	}
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveAccount(ctx, tx, tenant, account); err != nil {
			return err
		}
		record := databaseAppleGrant{TenantID: tenant, AccountID: account, Audience: identity.Audience, SubjectHash: hashOpaque(identity.Subject), Ciphertext: ciphertext}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "account_id"}, {Name: "audience"}, {Name: "subject_hash"}}, DoUpdates: clause.AssignmentColumns([]string{"ciphertext"})}).Create(&record).Error
	})
}

func (store *DatabaseUserStore) captureErasureProviders(ctx context.Context, tx *gorm.DB, job databaseAccountErasure) error {
	var identities []databaseAccountIdentityRecord
	if err := tx.Where("tenant_id = ? AND account_id = ?", job.TenantID, *job.AccountID).Find(&identities).Error; err != nil {
		return err
	}
	subjects := map[string]bool{}
	for _, identity := range identities {
		if identity.Provider == accountProviderApple {
			subjects[identity.ProviderID] = false
		}
	}
	if len(subjects) > 0 {
		if store.providerGrantCipher == nil {
			return errors.New("account.erasure.grant_cipher_unavailable")
		}
		var records []databaseAppleGrant
		if err := tx.Where("tenant_id = ? AND account_id = ?", job.TenantID, *job.AccountID).Order("subject_hash,audience").Find(&records).Error; err != nil {
			return err
		}
		grants := []appleGrant{}
		for _, record := range records {
			clear, err := store.providerGrantCipher.OpenProviderGrant(appleGrantBinding(job.TenantID, *job.AccountID, record.Audience), record.Ciphertext)
			if err != nil {
				return err
			}
			var grant appleGrant
			if err := json.Unmarshal(clear, &grant); err != nil {
				return err
			}
			if _, exists := subjects[grant.Subject]; !exists || grant.Audience != record.Audience || hashOpaque(grant.Subject) != record.SubjectHash || grant.RefreshToken == "" {
				return errors.New("account.erasure.invalid_apple_grant")
			}
			subjects[grant.Subject] = true
			grants = append(grants, grant)
		}
		state := providerPending
		names := make([]string, 0, len(subjects))
		for subject := range subjects {
			names = append(names, subject)
		}
		sort.Strings(names)
		for _, subject := range names {
			if !subjects[subject] {
				state = providerManual
				grants = append(grants, appleGrant{Subject: subject, IssuedUnix: job.CreatedUnix})
			}
			if err := tx.Create(&databaseAppleErasureSubject{job.OperationID, job.TenantID, hashOpaque(subject)}).Error; err != nil {
				return err
			}
		}
		clear, err := json.Marshal(appleErasureSnapshot{job.NotificationAudience, grants})
		if err != nil {
			return err
		}
		ciphertext, err := store.providerGrantCipher.SealProviderGrant(appleErasureBinding(job.TenantID, job.OperationID), clear)
		if err != nil {
			return err
		}
		if err := tx.Create(&databaseErasureProvider{OperationID: job.OperationID, Provider: accountProviderApple, TenantID: job.TenantID, State: state, Ciphertext: ciphertext}).Error; err != nil {
			return err
		}
	}
	var github databaseGitHubCredential
	err := tx.Where("tenant_id = ? AND user_id = ?", job.TenantID, *job.UserID).Take(&github).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if store.providerGrantCipher == nil {
		return errors.New("account.erasure.grant_cipher_unavailable")
	}
	subjectHash := ""
	for _, identity := range identities {
		if identity.Provider == accountProviderGitHub {
			subjectHash = hashOpaque(identity.ProviderID)
		}
	}
	clear, err := json.Marshal(githubErasureGrant{*job.AccountID, *job.UserID, github.Ciphertext})
	if err != nil {
		return err
	}
	ciphertext, err := store.providerGrantCipher.SealProviderGrant(providerErasureBinding(job.TenantID, job.OperationID, accountProviderGitHub), clear)
	if err != nil {
		return err
	}
	return tx.Create(&databaseErasureProvider{OperationID: job.OperationID, Provider: accountProviderGitHub, TenantID: job.TenantID, SubjectHash: subjectHash, State: providerPending, Ciphertext: ciphertext}).Error

}

// AppleAccountRevoker revokes operation-owned grants after local account removal.
type AppleAccountRevoker struct {
	accounts *DatabaseUserStore
	config   func(context.Context, string) (AppleOAuthConfig, error)
	client   *http.Client
}

// NewAppleAccountRevoker selects current tenant credentials and a bounded Apple transport.
func NewAppleAccountRevoker(accounts *DatabaseUserStore, config func(context.Context, string) (AppleOAuthConfig, error), client *http.Client) *AppleAccountRevoker {
	if client == nil {
		client = resolveAppleOAuthHTTPClient()
	}
	return &AppleAccountRevoker{accounts, config, client}
}

// RevokeAccountProvider is unsupported without the durable operation grant snapshot.
func (revoker *AppleAccountRevoker) RevokeAccountProvider(context.Context, string, string, string) error {
	return errors.New("account.erasure.operation_required")
}

func (revoker *AppleAccountRevoker) revokeErasureProvider(ctx context.Context, job databaseAccountErasure, obligation databaseErasureProvider) error {
	if obligation.Provider != accountProviderApple {
		return errors.New("account.erasure.provider_revoker_unavailable")
	}

	clear, err := revoker.accounts.providerGrantCipher.OpenProviderGrant(appleErasureBinding(job.TenantID, job.OperationID), obligation.Ciphertext)
	if err != nil {
		return err
	}
	var snapshot appleErasureSnapshot
	if err := json.Unmarshal(clear, &snapshot); err != nil {
		return err
	}
	grants := snapshot.Grants
	if len(grants) == 0 {
		return errors.New("account.erasure.empty_apple_snapshot")
	}
	configured, err := revoker.config(ctx, job.TenantID)
	if err != nil {
		return err
	}
	for index := range snapshot.Grants {
		grant := snapshot.Grants[index]
		if grant.Revoked {
			continue
		}
		if grant.RefreshToken == "" {
			continue
		}
		config := configured
		allowed := grant.Audience == config.ClientID
		for _, audience := range config.NativeClientIDs {
			allowed = allowed || audience == grant.Audience
		}
		if !config.Enabled || !allowed || grant.RefreshToken == "" {
			return errors.New("account.erasure.apple_config_changed")
		}
		config.ClientID = grant.Audience
		secret, err := buildAppleClientSecret(config, NewSystemClock())
		if err != nil {
			return err
		}
		form := url.Values{"client_id": {grant.Audience}, "client_secret": {secret}, "token": {grant.RefreshToken}, "token_type_hint": {"refresh_token"}}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, appleRevokeEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := revoker.client.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("account.erasure.apple_revoke_status: %d", response.StatusCode)
		}
		snapshot.Grants[index].Revoked = true
		snapshot.Grants[index].RefreshToken = ""
		if err := revoker.accounts.persistAppleSnapshot(ctx, job, &snapshot); err != nil {
			return err
		}
	}
	for _, grant := range snapshot.Grants {
		if !grant.Revoked && grant.RefreshToken == "" {
			return errAppleManual
		}
	}
	return nil
}

var errAppleManual = errors.New(appleManualReason)

func (store *DatabaseUserStore) snapshotClaimedErasure(ctx context.Context, job databaseAccountErasure) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		fenced := tx.Model(&databaseAccountErasure{}).Where("operation_id = ? AND lease_token = ? AND provider_snapshot = ?", job.OperationID, job.LeaseToken, false).Update("provider_snapshot", true)
		if fenced.Error != nil {
			return fenced.Error
		}
		if fenced.RowsAffected != 1 {
			return errErasureLeaseLost
		}
		return store.captureErasureProviders(ctx, tx, job)
	})
}

func (coordinator *AccountErasureCoordinator) revokeProviders(ctx context.Context, job databaseAccountErasure) error {
	var providers []databaseErasureProvider
	if err := coordinator.accounts.db.WithContext(ctx).Where("operation_id = ? AND state <> ?", job.OperationID, providerRevoked).Order("provider").Find(&providers).Error; err != nil {
		return err
	}
	for _, obligation := range providers {

		if coordinator.provider == nil {
			if obligation.State == providerManual {
				return errAppleManual
			}
			return errors.New("account.erasure.provider_revoker_unavailable")
		}
		var err error
		if revoker, ok := coordinator.provider.(interface {
			revokeErasureProvider(context.Context, databaseAccountErasure, databaseErasureProvider) error
		}); ok && obligation.Provider == accountProviderApple {
			err = revoker.revokeErasureProvider(ctx, job, obligation)
		} else if obligation.Provider == accountProviderGitHub {
			clear, decodeErr := coordinator.accounts.providerGrantCipher.OpenProviderGrant(providerErasureBinding(job.TenantID, job.OperationID, accountProviderGitHub), obligation.Ciphertext)
			var grant githubErasureGrant
			if decodeErr == nil {
				decodeErr = json.Unmarshal(clear, &grant)
			}
			if decodeErr != nil {
				err = decodeErr
			} else {
				err = coordinator.provider.RevokeAccountProvider(ctx, job.TenantID, grant.AccountID, obligation.Provider)
			}
		} else if job.AccountID != nil {
			err = coordinator.provider.RevokeAccountProvider(ctx, job.TenantID, *job.AccountID, obligation.Provider)
		} else {
			err = errors.New("account.erasure.provider_snapshot_unsupported")
		}
		if err != nil {
			return err
		}
		now := coordinator.accounts.now().UTC().Unix()
		changed := coordinator.accounts.db.WithContext(ctx).Model(&databaseErasureProvider{}).Where("operation_id = ? AND provider = ? AND EXISTS (SELECT 1 FROM account_erasures WHERE operation_id = ? AND lease_token = ? AND lease_until_unix > ?)", job.OperationID, obligation.Provider, job.OperationID, job.LeaseToken, now).Updates(map[string]any{"state": providerRevoked, "ciphertext": nil, "subject_hash": ""})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return errErasureLeaseLost
		}
	}
	return nil
}

func (store *DatabaseUserStore) finishErasure(ctx context.Context, job databaseAccountErasure) error {
	now := store.now().UTC().Unix()
	changed := store.db.WithContext(ctx).Model(&databaseAccountErasure{}).Where("operation_id = ? AND lease_token = ? AND lease_until_unix > ? AND account_state = ? AND NOT EXISTS (SELECT 1 FROM account_erasure_providers WHERE operation_id = ? AND state <> ?)", job.OperationID, job.LeaseToken, now, erasureAccountRemoved, job.OperationID, providerRevoked).Updates(map[string]any{"state": erasureCompleted, "reason": "", "phase": "", "lease_token": "", "lease_until_unix": 0, "next_attempt_unix": 0, "attempt_count": 0, "updated_unix": now, "expires_unix": now + int64(erasureReceiptTTL.Seconds())})
	if changed.Error != nil {
		return changed.Error
	}
	if changed.RowsAffected != 1 {
		return errErasureLeaseLost
	}
	return nil
}

type databaseAppleErasureSubject struct {
	OperationID string `gorm:"primaryKey"`
	TenantID    string `gorm:"index;not null"`
	SubjectHash string `gorm:"primaryKey;index"`
}

func (databaseAppleErasureSubject) TableName() string { return "apple_erasure_subjects" }

func (store *DatabaseUserStore) persistAppleSnapshot(ctx context.Context, job databaseAccountErasure, incoming *appleErasureSnapshot) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := store.now().UTC().Unix()
		fenced := tx.Model(&databaseAccountErasure{}).Where("operation_id = ? AND state = ? AND lease_token = ? AND lease_until_unix > ?", job.OperationID, erasureRunning, job.LeaseToken, now).Update("updated_unix", now)
		if fenced.Error != nil {
			return fenced.Error
		}
		if fenced.RowsAffected != 1 {
			return errErasureLeaseLost
		}
		var obligation databaseErasureProvider
		if err := tx.Where("operation_id = ? AND provider = ?", job.OperationID, accountProviderApple).Take(&obligation).Error; err != nil {
			return err
		}
		if obligation.State == providerRevoked {
			for index := range incoming.Grants {
				incoming.Grants[index].Revoked = true
				incoming.Grants[index].RefreshToken = ""
			}
			return nil
		}
		clear, err := store.providerGrantCipher.OpenProviderGrant(appleErasureBinding(job.TenantID, job.OperationID), obligation.Ciphertext)
		if err != nil {
			return err
		}
		var current appleErasureSnapshot
		if err := json.Unmarshal(clear, &current); err != nil {
			return err
		}
		if current.NotificationAudience != incoming.NotificationAudience || len(current.Grants) != len(incoming.Grants) {
			return errors.New("account.erasure.snapshot_identity_changed")
		}
		// Both snapshots have the same immutable captured order and grant identity.
		for index, proposed := range incoming.Grants {
			saved := current.Grants[index]
			if saved.Subject != proposed.Subject || saved.Audience != proposed.Audience || saved.IssuedUnix != proposed.IssuedUnix {
				return errors.New("account.erasure.snapshot_identity_changed")
			}
			current.Grants[index].Revoked = saved.Revoked || proposed.Revoked
			if current.Grants[index].Revoked {
				current.Grants[index].RefreshToken = ""
			}
		}
		encoded, err := json.Marshal(current)
		if err != nil {
			return err
		}
		ciphertext, err := store.providerGrantCipher.SealProviderGrant(appleErasureBinding(job.TenantID, job.OperationID), encoded)
		if err != nil {
			return err
		}
		changed := tx.Model(&databaseErasureProvider{}).Where("operation_id = ? AND provider = ? AND state <> ?", job.OperationID, accountProviderApple, providerRevoked).Update("ciphertext", ciphertext)
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return errErasureLeaseLost
		}
		*incoming = current
		return nil
	})
}

func (coordinator *AccountErasureCoordinator) resolveSnapshotConfiguration(ctx context.Context, job *databaseAccountErasure) error {
	var appleIdentities int64
	if err := coordinator.accounts.db.WithContext(ctx).Model(&databaseAccountIdentityRecord{}).Where("tenant_id = ? AND account_id = ? AND provider = ?", job.TenantID, *job.AccountID, accountProviderApple).Count(&appleIdentities).Error; err != nil {
		return err
	}
	if appleIdentities == 0 {
		return nil
	}
	if coordinator.appleConfig == nil {
		return errors.New("account.erasure.snapshot_configuration_unavailable")
	}
	config, err := coordinator.appleConfig(ctx, job.TenantID)
	if err != nil {
		return err
	}
	// An explicitly empty audience is unavailable; no audience is inferred.
	job.NotificationAudience = config.NotificationAudience
	return nil
}
