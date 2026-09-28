package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const CredentialsPath = "/api/management/provisioning-credentials"
const principalContextKey = "management.provisioning-credential"

type credentialInput struct {
	AppID       string   `json:"app_id"`
	Name        string   `json:"name"`
	Operations  []string `json:"operations" gorm:"serializer:json"`
	TenantIDs   []string `json:"tenant_ids" gorm:"serializer:json"`
	AllowCreate bool     `json:"allow_create"`
}
type provisioningCredential struct {
	AppID          string     `json:"app_id"`
	Name           string     `json:"name"`
	Operations     []string   `json:"operations" gorm:"serializer:json"`
	TenantIDs      []string   `json:"tenant_ids" gorm:"serializer:json"`
	AllowCreate    bool       `json:"allow_create"`
	ID             string     `json:"id"`
	OwnerAccountID string     `json:"-"`
	Digest         string     `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	Token          string     `json:"token,omitempty" gorm:"-"`
}

func (provisioningCredential) TableName() string { return "provisioning_credentials" }
func (store *Store) digest(value []byte) string {
	mac := hmac.New(sha256.New, store.digestKey)
	_, _ = mac.Write(value)
	return hex.EncodeToString(mac.Sum(nil))
}
func (store *Store) credential(ctx context.Context, authorization string) (provisioningCredential, error) {
	var row provisioningCredential
	if !strings.HasPrefix(authorization, "Bearer tauthp_") || len(authorization) > 160 {
		return row, failure(401, "provisioning_credential_invalid")
	}
	err := store.db.WithContext(ctx).First(&row, "digest = ? AND revoked_at IS NULL", store.digest([]byte(strings.TrimPrefix(authorization, "Bearer ")))).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = failure(401, "provisioning_credential_invalid")
	}
	return row, err
}
func provisioningPrincipal(ctx *gin.Context) *provisioningCredential {
	value, ok := ctx.Get(principalContextKey)
	if !ok {
		return nil
	}
	return value.(*provisioningCredential)
}
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func authorizeProvisioning(credential *provisioningCredential, method string, parts []string) error {
	operation := "read"
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		switch {
		case len(parts) == 0:
			if credential.AllowCreate {
				return nil
			}
			return failure(403, "creation_denied")
		case len(parts) == 1:
			operation = "suspend"
		case parts[1] == "configuration":
			operation = "configure"
		case parts[1] == "activations":
			operation = "activate"
		case parts[1] == "origin-proofs":
			operation = "proofs"
		default:
			return failure(403, "operation_denied")
		}
	}
	if !contains(credential.Operations, operation) {
		return failure(403, "operation_denied")
	}
	if len(parts) > 0 && !contains(credential.TenantIDs, parts[0]) {
		return failure(403, "tenant_grant_required")
	}
	return nil
}
func (management *Management) credentials(ctx *gin.Context, owner Owner) {
	id := strings.TrimPrefix(ctx.Request.URL.Path, CredentialsPath)
	id = strings.TrimPrefix(id, "/")
	store := management.store
	if ctx.Request.Method == "GET" || ctx.Request.Method == "HEAD" {
		if id != "" {
			var row provisioningCredential
			err := store.db.WithContext(ctx.Request.Context()).First(&row, "id = ? AND owner_account_id = ?", id, owner.ID).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = failure(404, "credential_not_found")
			}
			if err != nil {
				respondError(ctx, err)
				return
			}
			ctx.JSON(200, row)
			return
		}
		limit, cursor, err := pageQuery(ctx)
		if err != nil {
			respondError(ctx, err)
			return
		}
		rows := []provisioningCredential{}
		err = store.db.WithContext(ctx.Request.Context()).Where("owner_account_id = ? AND id > ?", owner.ID, cursor).Order("id").Limit(limit + 1).Find(&rows).Error
		if err != nil {
			respondError(ctx, err)
			return
		}
		next := ""
		if len(rows) > limit {
			rows = rows[:limit]
			next = rows[limit-1].ID
		}
		ctx.JSON(200, gin.H{"items": rows, "next_cursor": next})
		return
	}
	if ctx.Request.Method == "DELETE" && id != "" {
		management.mutation.Lock()
		defer management.mutation.Unlock()
		var row provisioningCredential
		err := store.db.WithContext(ctx.Request.Context()).First(&row, "id = ? AND owner_account_id = ?", id, owner.ID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = failure(404, "credential_not_found")
		}
		if err != nil {
			respondError(ctx, err)
			return
		}
		if row.RevokedAt == nil {
			err = store.db.WithContext(ctx.Request.Context()).Model(&provisioningCredential{}).Where("id = ?", id).Update("revoked_at", management.now().UTC()).Error
		}
		if err != nil {
			respondError(ctx, err)
			return
		}
		ctx.Status(204)
		return
	}
	if ctx.Request.Method != "POST" || id != "" {
		ctx.Header("Allow", "GET, HEAD, POST, OPTIONS")
		respondError(ctx, failure(405, "method_not_allowed"))
		return
	}
	data, err := readManagementBody(ctx)
	if err != nil {
		respondError(ctx, err)
		return
	}
	var input credentialInput
	if err := decodeBody(data, &input); err != nil {
		respondError(ctx, err)
		return
	}
	if strings.TrimSpace(input.AppID) == "" || strings.TrimSpace(input.Name) == "" || len(input.Name) > 120 || len(input.Operations) == 0 || len(input.TenantIDs) > 100 || input.TenantIDs == nil {
		respondError(ctx, failure(422, "credential_invalid"))
		return
	}
	seen := map[string]bool{}
	for _, operation := range input.Operations {
		if !contains([]string{"read", "configure", "activate", "suspend", "proofs"}, operation) || seen[operation] {
			respondError(ctx, failure(422, "credential_operations_invalid"))
			return
		}
		seen[operation] = true
	}
	key := ctx.GetHeader("Idempotency-Key")
	if len(key) < 1 || len(key) > 128 {
		respondError(ctx, failure(400, "idempotency_key_required"))
		return
	}
	management.mutation.Lock()
	defer management.mutation.Unlock()
	encoded, err := json.Marshal(input)
	if err != nil {
		respondError(ctx, err)
		return
	}
	digest := store.digest(encoded)
	var result provisioningCredential
	err = store.db.WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
			return err
		}
		var receipt receiptRecord
		err := tx.First(&receipt, "owner_account_id = ? AND path = ? AND key = ?", owner.ID, CredentialsPath, key).Error
		if err == nil {
			if receipt.Digest != digest {
				return failure(409, "idempotency_conflict")
			}
			return json.Unmarshal([]byte(receipt.Response), &result)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		local := store.local(tx)
		if _, err := local.app(ctx.Request.Context(), owner.ID, input.AppID); err != nil {
			return err
		}
		for _, tenantID := range input.TenantIDs {
			tenant, err := local.tenant(ctx.Request.Context(), owner.ID, tenantID)
			if err != nil {
				return err
			}
			if tenant.AppID != input.AppID {
				return failure(422, "credential_app_mismatch")
			}
		}
		var count int64
		if err := tx.Model(&provisioningCredential{}).Where("owner_account_id = ? AND revoked_at IS NULL", owner.ID).Count(&count).Error; err != nil {
			return err
		}
		if count >= 20 {
			return failure(429, "credential_limit")
		}
		token := "tauthp_" + newID() + newID()
		result = provisioningCredential{AppID: input.AppID, Name: input.Name, Operations: input.Operations, TenantIDs: input.TenantIDs, AllowCreate: input.AllowCreate, ID: newID(), OwnerAccountID: owner.ID, Digest: store.digest([]byte(token)), CreatedAt: management.now().UTC()}
		if err := tx.Create(&result).Error; err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := tx.Create(&receiptRecord{OwnerAccountID: owner.ID, Path: CredentialsPath, Key: key, Digest: digest, Response: string(encoded), Status: 201, Location: CredentialsPath + "/" + result.ID}).Error; err != nil {
			return err
		}
		result.Token = token
		return nil
	})
	if err != nil {
		respondError(ctx, err)
		return
	}
	respond(ctx, resourceResult{Status: 201, Body: result, Location: CredentialsPath + "/" + result.ID})
}

func credentialTenantScope(ctx *gin.Context) func(*gorm.DB) *gorm.DB {
	principal := provisioningPrincipal(ctx)
	return func(query *gorm.DB) *gorm.DB {
		if principal != nil {
			return query.Where("id IN ?", principal.TenantIDs)
		}
		return query
	}
}
