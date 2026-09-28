package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/internal/oauthserver"
	"gorm.io/gorm"
)

type auditEvent struct {
	ID             string    `json:"id"`
	ActorAccountID string    `json:"actor_account_id"`
	TenantID       string    `json:"tenant_id"`
	Operation      string    `json:"operation"`
	Revision       int64     `json:"revision"`
	Result         string    `json:"result"`
	CreatedAt      time.Time `json:"created_at"`
}

func (auditEvent) TableName() string { return "tenant_audit_events" }
func (management *Management) read(ctx *gin.Context, owner string, parts []string) (resourceResult, error) {
	if len(parts) == 3 && parts[1] == "setup-checks" {
		var row setupCheck
		err := management.store.db.WithContext(ctx.Request.Context()).First(&row, "id = ? AND tenant_id = ?", parts[2], parts[0]).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = failure(404, "setup_check_not_found")
		}
		return resourceResult{Status: 200, Body: row}, err
	}

	if len(parts) > 1 && (parts[1] == "integration" || parts[1] == "reauthentications" || parts[1] == "key-exports") {
		return management.store.integrationResource(ctx.Request.Context(), owner, parts)
	}
	store := management.store
	if len(parts) == 1 {
		row, err := store.tenant(ctx.Request.Context(), owner, parts[0])
		return resourceResult{Status: 200, Body: row, ETag: tenantETag(row.Version)}, err
	}
	if len(parts) == 2 && parts[1] == "configuration" {
		view, err := store.configurationView(ctx.Request.Context(), parts[0])
		return resourceResult{Status: 200, Body: view, ETag: configETag(view.Revision)}, err
	}
	if len(parts) == 5 {
		var row originVerification
		err := store.db.WithContext(ctx.Request.Context()).First(&row, "tenant_id = ? AND proof_id = ? AND id = ?", parts[0], parts[2], parts[4]).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = failure(404, "verification_not_found")
		}
		return resourceResult{Status: 200, Body: row}, err
	}
	if len(parts) == 3 && parts[1] == "origin-proofs" {
		var row originProof
		err := store.db.WithContext(ctx.Request.Context()).First(&row, "tenant_id = ? AND id = ?", parts[0], parts[2]).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = failure(404, "proof_not_found")
		}
		return resourceResult{Status: 200, Body: row}, err
	}
	if len(parts) == 3 {
		var row activation
		err := store.db.WithContext(ctx.Request.Context()).First(&row, "tenant_id = ? AND id = ?", parts[0], parts[2]).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = failure(404, "activation_not_found")
		}
		return resourceResult{Status: 200, Body: row}, err
	}
	limit, cursor, err := pageQuery(ctx)
	if err != nil {
		return resourceResult{}, err
	}
	query := store.db.WithContext(ctx.Request.Context()).Where("id > ?", cursor).Order("id").Limit(limit + 1)
	var items any
	var next string
	if len(parts) == 0 {
		rows := []tenantRecord{}
		if appID, present := ctx.GetQuery("app_id"); present {
			if _, err := store.app(ctx.Request.Context(), owner, appID); err != nil {
				return resourceResult{}, err
			}
			query = query.Where("app_id = ?", appID)
		}
		if err := query.Where("owner_account_id = ?", owner).Scopes(credentialTenantScope(ctx)).Find(&rows).Error; err != nil {
			return resourceResult{}, err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			next = rows[limit-1].ID
		}
		items = rows
	} else {
		query = query.Where("tenant_id = ?", parts[0])
		switch parts[1] {
		case "origin-proofs":
			rows := []originProof{}
			if err := query.Find(&rows).Error; err != nil {
				return resourceResult{}, err
			}
			if len(rows) > limit {
				rows = rows[:limit]
				next = rows[limit-1].ID
			}
			items = rows
		case "activations":
			rows := []activation{}
			if err := query.Find(&rows).Error; err != nil {
				return resourceResult{}, err
			}
			if len(rows) > limit {
				rows = rows[:limit]
				next = rows[limit-1].ID
			}
			items = rows
		case "setup-checks":
			rows := []setupCheck{}
			if err := query.Find(&rows).Error; err != nil {
				return resourceResult{}, err
			}
			if len(rows) > limit {
				rows = rows[:limit]
				next = rows[limit-1].ID
			}
			items = rows
		case "audit-events":
			rows := []auditEvent{}
			if err := query.Find(&rows).Error; err != nil {
				return resourceResult{}, err
			}
			if len(rows) > limit {
				rows = rows[:limit]
				next = rows[limit-1].ID
			}
			items = rows
		}
	}
	return resourceResult{Status: 200, Body: gin.H{"items": items, "next_cursor": next}}, nil
}
func (management *Management) write(ctx *gin.Context, store *Store, owner string, parts []string, data []byte) (resourceResult, PreparedRuntime, string, error) {
	var result resourceResult
	var candidate PreparedRuntime
	var suspended string
	if len(parts) == 0 {
		var body struct {
			ID                string `json:"id"`
			AppID             string `json:"app_id"`
			Name              string `json:"name"`
			Environment       string `json:"environment"`
			ApplicationOrigin string `json:"application_origin"`
			GoogleWebClientID string `json:"google_web_client_id"`
		}
		if err := decodeBody(data, &body); err != nil {
			return result, nil, "", err
		}
		if strings.TrimSpace(body.Name) == "" || len(body.Name) > 120 || len(body.Environment) > 40 {
			return result, nil, "", failure(422, "tenant_invalid")
		}
		if provisioningPrincipal(ctx) != nil && (body.ID == "" || body.ApplicationOrigin != "" || body.GoogleWebClientID != "") {
			return result, nil, "", failure(422, "provisioning_creation_invalid")
		}
		if provisioningPrincipal(ctx) == nil {
			if strings.TrimSpace(body.ApplicationOrigin) == "" || !googleWebClientPattern.MatchString(body.GoogleWebClientID) || len(body.GoogleWebClientID) > 256 {
				return result, nil, "", failure(422, "tenant_configuration_required")
			}
			if _, err := canonicalAddress(body.ApplicationOrigin, true); err != nil {
				return result, nil, "", err
			}
		}
		if principal := provisioningPrincipal(ctx); principal != nil {
			if body.AppID != "" {
				return result, nil, "", failure(422, "provisioning_creation_invalid")
			}
			body.AppID = principal.AppID
		}
		if strings.TrimSpace(body.AppID) == "" {
			return result, nil, "", failure(422, "app_required")
		}
		if _, err := store.app(ctx.Request.Context(), owner, body.AppID); err != nil {
			return result, nil, "", err
		}
		var count int64
		if err := store.db.Model(&tenantRecord{}).Where("owner_account_id = ?", owner).Count(&count).Error; err != nil {
			return result, nil, "", err
		}
		if count >= maxTenantsPerOwner {
			return result, nil, "", failure(429, "tenant_limit")
		}
		entropy := make([]byte, 16)
		_, _ = rand.Read(entropy)
		row := tenantRecord{AppID: body.AppID, ID: hex.EncodeToString(entropy), OwnerAccountID: owner, Name: body.Name, Environment: body.Environment, Version: 1, State: "draft"}
		if body.ID != "" {
			if provisioningPrincipal(ctx) == nil {
				return result, nil, "", failure(403, "tenant_id_operator_only")
			}
			if !regexp.MustCompile("^[a-z0-9][a-z0-9_-]{1,63}$").MatchString(body.ID) || body.ID == ConsoleTenantID {
				return result, nil, "", failure(422, "tenant_id_invalid")
			}
			row.ID = body.ID
		}
		var existing int64
		if err := store.db.Model(&tenantRecord{}).Where("id = ?", row.ID).Count(&existing).Error; err != nil {
			return result, nil, "", err
		}
		if existing > 0 {
			return result, nil, "", failure(409, "tenant_exists")
		}
		if err := store.db.Create(&row).Error; err != nil {
			return result, nil, "", err
		}
		if principal := provisioningPrincipal(ctx); principal != nil {
			grants := append(principal.TenantIDs, row.ID)
			encoded, err := json.Marshal(grants)
			if err != nil {
				return result, nil, "", err
			}
			if err := store.db.Model(&provisioningCredential{}).Where("id = ?", principal.ID).Update("tenant_ids", string(encoded)).Error; err != nil {
				return result, nil, "", err
			}
		}
		file := initialConfiguration(row.ID, row.Name)
		if provisioningPrincipal(ctx) == nil {
			file.TenantOrigins = []string{body.ApplicationOrigin}
			file.GoogleWebClientID = body.GoogleWebClientID
			address, _ := canonicalAddress(body.ApplicationOrigin, true)
			local := isLocalHostname(address.Hostname())
			if local {
				file.AllowInsecureHTTP = true
				file.RequireTenantHeader = true
			}
			if err := store.saveConfiguration(ctx.Request.Context(), file, 1, "owner-configuration"); err != nil {
				return result, nil, "", err
			}
			record := configurationRecord{TenantID: row.ID, Revision: 1, LocalDevelopment: local}
			if err := store.db.Model(&configurationRecord{}).Where("tenant_id = ? AND revision = ?", row.ID, 1).Update("local_development", local).Error; err != nil {
				return result, nil, "", err
			}
			var err error
			candidate, err = management.publishConfiguration(ctx, store, &row, file, record)
			if err != nil {
				return result, candidate, "", err
			}
		} else if err := store.saveConfiguration(ctx.Request.Context(), file, 1, "provisioning-pending"); err != nil {
			return result, nil, "", err
		}
		if err := store.audit(ctx.Request.Context(), owner, row.ID, "tenant.created", "succeeded", 1); err != nil {
			return result, candidate, "", err
		}
		return resourceResult{Status: 201, Body: row, Location: TenantsPath + "/" + row.ID, ETag: tenantETag(row.Version)}, candidate, "", nil
	}
	row, err := store.tenant(ctx.Request.Context(), owner, parts[0])
	if err != nil {
		return result, nil, "", err
	}
	if len(parts) == 1 {
		if err := requireMatch(ctx.GetHeader("If-Match"), tenantETag(row.Version)); err != nil {
			return result, nil, "", err
		}
		var body struct {
			Name        *string `json:"name"`
			Environment *string `json:"environment"`
			State       *string `json:"state"`
		}
		if err := decodeBody(data, &body); err != nil {
			return result, nil, "", err
		}
		if provisioningPrincipal(ctx) != nil && (body.Name != nil || body.Environment != nil) {
			return result, nil, "", failure(403, "operation_denied")
		}
		if body.Name == nil && body.Environment == nil && body.State == nil {
			return result, nil, "", failure(422, "patch_empty")
		}
		if body.Name != nil {
			if strings.TrimSpace(*body.Name) == "" || len(*body.Name) > 120 {
				return result, nil, "", failure(422, "name_invalid")
			}
			row.Name = *body.Name
		}
		if body.Environment != nil {
			if len(*body.Environment) > 40 {
				return result, nil, "", failure(422, "environment_invalid")
			}
			row.Environment = *body.Environment
		}
		if body.State != nil {
			if *body.State != "suspended" {
				return result, nil, "", failure(422, "state_invalid")
			}
			row.State = "suspended"
			row.SuspensionPending = true
			suspended = row.ID
		}
		row.Version++
		if err := store.db.Model(&tenantRecord{}).Where("id = ?", row.ID).Updates(map[string]any{"name": row.Name, "environment": row.Environment, "state": row.State, "suspension_pending": row.SuspensionPending, "version": row.Version, "updated_at": management.now().UTC()}).Error; err != nil {
			return result, nil, "", err
		}
		if suspended != "" {
			config, err := store.RuntimeTenants(ctx.Request.Context())
			if err != nil {
				return result, nil, "", err
			}
			candidate, err = management.build(ctx.Request.Context(), config)
			if err != nil {
				return result, nil, "", failure(422, "runtime_invalid")
			}
		}
		if err := store.audit(ctx.Request.Context(), owner, row.ID, "tenant.updated", "succeeded", 0); err != nil {
			return result, candidate, "", err
		}
		return resourceResult{Status: 200, Body: row, ETag: tenantETag(row.Version)}, candidate, suspended, nil
	}
	switch parts[1] {
	case "configuration":
		file, record, err := store.configuration(ctx.Request.Context(), row.ID, 0)
		if err != nil {
			return result, nil, "", err
		}
		if err := requireMatch(ctx.GetHeader("If-Match"), configETag(record.Revision)); err != nil {
			return result, nil, "", err
		}
		var input configurationInput
		if err := decodeBody(data, &input); err != nil {
			return result, nil, "", err
		}
		if provisioningPrincipal(ctx) != nil && input.Provisioning == nil {
			return result, nil, "", failure(422, "provisioning_configuration_required")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return result, nil, "", failure(400, "body_invalid")
		}
		if input.Provisioning != nil {
			if len(fields) != 1 {
				return result, nil, "", failure(422, "configuration_shape_invalid")
			}
			result, err := store.saveProvisioning(ctx, row, *input.Provisioning)
			return result, nil, "", err
		}
		for _, name := range []string{"google_web_client_id", "frontend_origins", "api_base_url", "local_development", "session_ttl", "refresh_ttl"} {
			if _, ok := fields[name]; !ok {
				return result, nil, "", failure(422, "configuration_shape_invalid")
			}
		}
		if err := validateConfiguration(input); err != nil {
			return result, nil, "", err
		}
		file.RequireTenantHeader = input.LocalDevelopment
		file.GoogleWebClientID = input.GoogleWebClientID
		file.TenantOrigins = input.FrontendOrigins
		file.SessionTTL = input.SessionTTL
		file.RefreshTTL = input.RefreshTTL
		if input.LocalDevelopment {
			file.AllowInsecureHTTP = true
		} else {
			file.AllowInsecureHTTP = false
		}
		file.DisplayName = row.Name
		record.Revision++
		record.APIBaseURL = input.APIBaseURL
		record.LocalDevelopment = input.LocalDevelopment
		if err := store.saveConfiguration(ctx.Request.Context(), file, record.Revision, "owner-configuration"); err != nil {
			return result, nil, "", err
		}
		if err := store.db.Model(&configurationRecord{}).Where("tenant_id = ? AND revision = ?", row.ID, record.Revision).Updates(map[string]any{"api_base_url": record.APIBaseURL, "local_development": record.LocalDevelopment}).Error; err != nil {
			return result, nil, "", err
		}
		if row.State != "suspended" {
			candidate, err = management.publishConfiguration(ctx, store, &row, file, record)
			if err != nil {
				return result, candidate, "", err
			}
		}
		if err := store.audit(ctx.Request.Context(), owner, row.ID, "configuration.saved", "succeeded", record.Revision); err != nil {
			return result, candidate, "", err
		}
		return resourceResult{Status: 200, Body: publicConfiguration(file, record), ETag: configETag(record.Revision)}, candidate, "", nil
	case "reauthentications", "key-exports":
		result, err = management.integrationWrite(ctx, store, owner, parts, data)
	case "origin-proofs":
		result, err = management.proofWrite(ctx, store, row, data, parts)
	case "activations":
		result, candidate, err = management.activate(ctx, store, row, data)
	}
	return result, candidate, "", err
}

// RevokeSuspended clears issuance that an in-flight request completed before its snapshot retired.
// Startup also applies this operation before accepting requests after a crash.
func (store *Store) RevokeSuspended(ctx context.Context, id string) error {
	return store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row tenantRecord
		if err := tx.First(&row, "id = ? AND state = ?", id, "suspended").Error; err != nil {
			return err
		}
		if err := authkit.RevokeTenantSessions(ctx, tx, id); err != nil {
			return err
		}
		if err := oauthserver.RevokeTenantGrants(ctx, tx, id, time.Now().UTC().Unix()); err != nil {
			return err
		}
		if err := tx.Model(&tenantRecord{}).Where("id = ?", id).Update("suspension_pending", false).Error; err != nil {
			return err
		}
		return store.local(tx).audit(ctx, row.OwnerAccountID, id, "tenant.suspended", "succeeded", 0)
	})
}
func (store *Store) ResumeSuspensions(ctx context.Context) error {
	var rows []tenantRecord
	if err := store.db.WithContext(ctx).Where("state = ?", "suspended").Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		if err := store.RevokeSuspended(ctx, row.ID); err != nil {
			return err
		}
	}
	return nil
}
