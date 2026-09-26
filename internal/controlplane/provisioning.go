package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/deploymentconfig"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

type provisioningInput struct {
	Generation   int64           `json:"generation"`
	Contribution json.RawMessage `json:"contribution"`
}
type provisioningBinding struct {
	TenantID          string `json:"tenant_id"`
	ContributionOwner string `json:"contribution_owner"`
	ContributionID    string `json:"contribution_id"`
	Generation        int64  `json:"generation"`
	Revision          int64  `json:"revision"`
	Digest            string `json:"-"`
}

func (provisioningBinding) TableName() string { return "provisioning_bindings" }
func (store *Store) configurationView(ctx context.Context, id string) (configurationView, error) {
	file, row, err := store.configuration(ctx, id, 0)
	if err != nil {
		return configurationView{}, err
	}
	view := publicConfiguration(file, row)
	var binding provisioningBinding
	err = store.db.WithContext(ctx).First(&binding, "tenant_id = ?", id).Error
	if err == nil {
		view.Provisioning = &binding
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return view, err
	}
	return view, nil
}
func (store *Store) saveProvisioning(ctx *gin.Context, tenant tenantRecord, input provisioningInput) (resourceResult, error) {
	if provisioningPrincipal(ctx) == nil {
		return resourceResult{}, failure(403, "provisioning_credential_required")
	}
	if input.Generation < 1 {
		return resourceResult{}, failure(422, "generation_invalid")
	}
	projection, err := deploymentconfig.ResolveContribution(input.Contribution)
	if err != nil {
		return resourceResult{}, failure(422, "contribution_invalid")
	}
	if projection.Tenant.ID != tenant.ID {
		return resourceResult{}, failure(422, "contribution_tenant_mismatch")
	}
	var canonical any
	if err := json.Unmarshal(input.Contribution, &canonical); err != nil {
		return resourceResult{}, failure(400, "contribution_invalid")
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return resourceResult{}, err
	}
	digest := store.digest(encoded)
	_, current, err := store.configuration(ctx.Request.Context(), tenant.ID, 0)
	if err != nil {
		return resourceResult{}, err
	}
	var binding provisioningBinding
	err = store.db.First(&binding, "tenant_id = ?", tenant.ID).Error
	if err == nil {
		if binding.ContributionOwner != projection.Owner || binding.ContributionID != projection.ContributionID {
			return resourceResult{}, failure(409, "contribution_binding_conflict")
		}
		if binding.Revision != current.Revision {
			return resourceResult{}, failure(412, "provisioning_revision_conflict")
		}
		if input.Generation < binding.Generation {
			return resourceResult{}, failure(409, "generation_conflict")
		}
		if input.Generation == binding.Generation {
			if binding.Digest != digest {
				return resourceResult{}, failure(409, "generation_conflict")
			}
			view, err := store.configurationView(ctx.Request.Context(), tenant.ID)
			return resourceResult{Status: 200, Body: view, ETag: configETag(current.Revision)}, err
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return resourceResult{}, err
	}
	if tenant.State == "suspended" {
		return resourceResult{}, failure(409, "tenant_suspended")
	}
	if tenant.ActiveRevision != nil {
		active, _, err := store.configuration(ctx.Request.Context(), tenant.ID, *tenant.ActiveRevision)
		if err != nil {
			return resourceResult{}, err
		}
		effective, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{active}})
		if err != nil {
			return resourceResult{}, err
		}
		proposed, err := tenants.LoadResolvedConfig(tenants.FileDocument{Tenants: []tenants.FileTenant{projection.Tenant}})
		if err != nil {
			return resourceResult{}, err
		}
		currentTenant, nextTenant := effective.Tenants()[0], proposed.Tenants()[0]
		if !bytes.Equal(currentTenant.SigningKey(), nextTenant.SigningKey()) || currentTenant.SessionCookieName() != nextTenant.SessionCookieName() || currentTenant.RefreshCookieName() != nextTenant.RefreshCookieName() || currentTenant.CookieDomain() != nextTenant.CookieDomain() {
			return resourceResult{}, failure(409, "validator_contract_conflict")
		}
	}

	next := projection.Tenant
	local := false
	for _, raw := range next.TenantOrigins {
		address, err := url.Parse(raw)
		if err != nil {
			return resourceResult{}, failure(422, "origin_invalid")
		}
		if address.Hostname() == "localhost" || address.Hostname() == "127.0.0.1" || address.Hostname() == "::1" {
			local = true
		}
	}
	next.RequireTenantHeader = local
	if local {
		next.AllowInsecureHTTP = true
	}
	revision := current.Revision + 1
	if err := store.saveConfiguration(ctx.Request.Context(), next, revision, "gateway-draft"); err != nil {
		return resourceResult{}, err
	}
	if err := store.db.Model(&configurationRecord{}).Where("tenant_id = ? AND revision = ?", tenant.ID, revision).Updates(map[string]any{"api_base_url": current.APIBaseURL, "local_development": local, "operator_integration": true}).Error; err != nil {
		return resourceResult{}, err
	}
	binding = provisioningBinding{TenantID: tenant.ID, ContributionOwner: projection.Owner, ContributionID: projection.ContributionID, Generation: input.Generation, Revision: revision, Digest: digest}
	// A contribution and a tenant have one stable binding across credential replacement.
	if err := store.db.Where("tenant_id = ?", tenant.ID).Delete(&provisioningBinding{}).Error; err != nil {
		return resourceResult{}, err
	}
	if err := store.db.Create(&binding).Error; err != nil {
		return resourceResult{}, failure(409, "contribution_binding_conflict")
	}
	if err := store.audit(ctx.Request.Context(), tenant.OwnerAccountID, tenant.ID, "configuration.provisioned", "succeeded", revision); err != nil {
		return resourceResult{}, err
	}
	view, err := store.configurationView(ctx.Request.Context(), tenant.ID)
	return resourceResult{Status: 200, Body: view, ETag: configETag(revision)}, err
}
