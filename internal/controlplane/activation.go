package controlplane

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
	"gorm.io/gorm"
)

type originProof struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Revision   int64      `json:"revision"`
	Hostname   string     `json:"hostname"`
	Name       string     `json:"name"`
	Value      string     `json:"value"`
	State      string     `json:"state"`
	ExpiresAt  time.Time  `json:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at"`
}

func (originProof) TableName() string { return "tenant_origin_proofs" }

type originVerification struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ProofID   string    `json:"proof_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

func (originVerification) TableName() string { return "tenant_origin_verifications" }

type activation struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Revision  int64     `json:"revision"`
	State     string    `json:"state"`
	ErrorCode string    `json:"error_code"`
	CreatedAt time.Time `json:"created_at"`
}

func (activation) TableName() string { return "tenant_activations" }
func (management *Management) proofWrite(ctx *gin.Context, store *Store, tenant tenantRecord, data []byte, parts []string) (resourceResult, error) {
	var proof originProof
	if len(parts) == 2 {
		var input struct {
			Revision int64  `json:"revision"`
			Hostname string `json:"hostname"`
		}
		if err := decodeBody(data, &input); err != nil {
			return resourceResult{}, err
		}
		file, row, err := store.configuration(ctx.Request.Context(), tenant.ID, 0)
		if err != nil {
			return resourceResult{}, err
		}
		if input.Revision != row.Revision {
			return resourceResult{}, failure(412, "revision_conflict")
		}
		found := false
		for _, raw := range append(file.TenantOrigins, row.APIBaseURL) {
			parsed, err := url.Parse(raw)
			if err == nil && parsed.Hostname() == input.Hostname && input.Hostname != "" {
				found = true
			}
		}
		if !found || input.Hostname == "localhost" || input.Hostname == "127.0.0.1" || input.Hostname == "::1" {
			return resourceResult{}, failure(422, "proof_hostname_invalid")
		}
		var count int64
		if err := store.db.Model(&originProof{}).Where("tenant_id = ? AND expires_at > ?", tenant.ID, management.now()).Count(&count).Error; err != nil {
			return resourceResult{}, err
		}
		if count >= 20 {
			return resourceResult{}, failure(429, "proof_limit")
		}
		proof = originProof{ID: newID(), TenantID: tenant.ID, Revision: row.Revision, Hostname: input.Hostname, Name: "_tauth-challenge." + input.Hostname, Value: "tauth=" + newID(), State: "pending", ExpiresAt: management.now().UTC().Add(15 * time.Minute)}
		if err := store.db.Create(&proof).Error; err != nil {
			return resourceResult{}, err
		}
	} else {
		if err := decodeBody(data, &struct{}{}); err != nil {
			return resourceResult{}, err
		}
		if err := store.db.First(&proof, "tenant_id = ? AND id = ?", tenant.ID, parts[2]).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return resourceResult{}, failure(404, "proof_not_found")
			}
			return resourceResult{}, err
		}
		now := management.now().UTC()
		if !now.Before(proof.ExpiresAt) {
			return resourceResult{}, failure(409, "proof_expired")
		}
		_, current, err := store.configuration(ctx.Request.Context(), tenant.ID, 0)
		if err != nil {
			return resourceResult{}, err
		}
		if current.Revision != proof.Revision {
			return resourceResult{}, failure(412, "revision_conflict")
		}
		lookupCtx, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
		defer cancel()
		values, err := management.lookupTXT(lookupCtx, proof.Name)
		if err != nil {
			return resourceResult{}, failure(503, "dns_unavailable")
		}
		found := false
		for _, value := range values {
			if value == proof.Value {
				found = true
			}
		}
		if !found {
			return resourceResult{}, failure(422, "dns_proof_missing")
		}
		proof.State = "verified"
		proof.VerifiedAt = &now
		if err := store.db.Model(&originProof{}).Where("id = ?", proof.ID).Updates(map[string]any{"state": proof.State, "verified_at": now}).Error; err != nil {
			return resourceResult{}, err
		}
	}
	if err := store.audit(ctx.Request.Context(), tenant.OwnerAccountID, tenant.ID, "origin-proof."+proof.State, "succeeded", proof.Revision); err != nil {
		return resourceResult{}, err
	}
	location := TenantsPath + "/" + tenant.ID + "/origin-proofs/" + proof.ID
	if len(parts) == 4 {
		verification := originVerification{ID: newID(), TenantID: tenant.ID, ProofID: proof.ID, State: "verified", CreatedAt: management.now().UTC()}
		if err := store.db.Create(&verification).Error; err != nil {
			return resourceResult{}, err
		}
		return resourceResult{Status: 201, Body: verification, Location: location + "/verifications/" + verification.ID}, nil
	}
	return resourceResult{Status: 201, Body: proof, Location: location}, nil
}
func (management *Management) checkOrigins(ctx context.Context, store *Store, tenant tenantRecord, origins []string, api string, local bool) error {
	console, err := store.Console(ctx)
	if err != nil {
		return err
	}
	document, err := store.ApplicationTenants(ctx)
	if err != nil {
		return err
	}
	for _, origin := range append(append([]string{}, origins...), api) {
		if origin == "" {
			continue
		}
		parsed, err := canonicalAddress(origin, local)
		if err != nil {
			return err
		}
		for _, reserved := range console.TenantOrigins {
			address, _ := url.Parse(reserved)
			if parsed.Hostname() == address.Hostname() && (!isLocalHostname(parsed.Hostname()) || origin == reserved) {
				return failure(409, "console_origin_reserved")
			}
		}
		if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1" {
			continue
		}
		// A production hostname has one active tenant authority.
		for _, other := range document.Tenants {
			if other.ID == tenant.ID {
				continue
			}
			for _, raw := range other.TenantOrigins {
				address, _ := url.Parse(raw)
				if address.Hostname() == parsed.Hostname() {
					return failure(409, "origin_conflict")
				}
			}
		}
		var otherAPIs []string
		if err := store.db.Table("tenant_configurations AS c").Select("c.api_base_url").Joins("JOIN tenants AS t ON t.id = c.tenant_id AND t.active_revision = c.revision").Where("t.state = ? AND t.id <> ?", "active", tenant.ID).Scan(&otherAPIs).Error; err != nil {
			return err
		}
		for _, raw := range otherAPIs {
			address, _ := url.Parse(raw)
			if address.Hostname() == parsed.Hostname() {
				return failure(409, "origin_conflict")
			}
		}

	}
	return nil
}
func (management *Management) activate(ctx *gin.Context, store *Store, tenant tenantRecord, data []byte) (resourceResult, PreparedRuntime, error) {
	if provisioningPrincipal(ctx) != nil && tenant.State == "suspended" {
		return resourceResult{}, nil, failure(409, "tenant_suspended")
	}
	if tenant.SuspensionPending {
		return resourceResult{}, nil, failure(409, "suspension_incomplete")
	}
	var input struct {
		Revision int64 `json:"revision"`
	}
	if err := decodeBody(data, &input); err != nil {
		return resourceResult{}, nil, err
	}
	file, row, err := store.configuration(ctx.Request.Context(), tenant.ID, 0)
	if err != nil {
		return resourceResult{}, nil, err
	}
	if err := requireMatch(ctx.GetHeader("If-Match"), configETag(row.Revision)); err != nil {
		return resourceResult{}, nil, err
	}
	if input.Revision != row.Revision {
		return resourceResult{}, nil, failure(412, "revision_conflict")
	}
	record := activation{ID: newID(), TenantID: tenant.ID, Revision: row.Revision, State: "succeeded", CreatedAt: management.now().UTC()}
	var candidate PreparedRuntime
	validation := management.checkOrigins(ctx.Request.Context(), store, tenant, file.TenantOrigins, row.APIBaseURL, row.LocalDevelopment)
	if len(file.TenantOrigins) == 0 {
		validation = failure(422, "configuration_incomplete")
	}
	if validation == nil {
		// The transaction's tentative revision is visible only to its snapshot builder.
		if err := store.db.Model(&tenantRecord{}).Where("id = ?", tenant.ID).Updates(map[string]any{"state": "active", "active_revision": row.Revision, "version": tenant.Version + 1}).Error; err != nil {
			return resourceResult{}, nil, err
		}
		config, err := store.RuntimeTenants(ctx.Request.Context())
		validation = err
		if validation == nil {
			candidate, validation = management.build(ctx.Request.Context(), config)
		}
		if validation != nil {
			if err := store.db.Model(&tenantRecord{}).Where("id = ?", tenant.ID).Updates(map[string]any{"state": tenant.State, "active_revision": tenant.ActiveRevision, "version": tenant.Version}).Error; err != nil {
				return resourceResult{}, candidate, err
			}
		}
	}
	status := 201
	if validation != nil {
		record.State = "failed"
		record.ErrorCode = "management.runtime_invalid"
		status = 422
		var typed *apiError
		if errors.As(validation, &typed) {
			record.ErrorCode = typed.Code
			status = typed.Status
		}
	}
	if err := store.db.Create(&record).Error; err != nil {
		return resourceResult{}, candidate, err
	}
	if err := store.audit(ctx.Request.Context(), tenant.OwnerAccountID, tenant.ID, "configuration.activated", record.State, row.Revision); err != nil {
		return resourceResult{}, candidate, err
	}
	body := any(record)
	if record.State == "failed" {
		body = gin.H{"code": record.ErrorCode, "message": strings.ReplaceAll(record.ErrorCode, "_", " "), "details": gin.H{"activation": record}, "request_id": newID()}
	}
	return resourceResult{Status: status, Body: body, Location: TenantsPath + "/" + tenant.ID + "/activations/" + record.ID}, candidate, nil
}

func isLocalHostname(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// publishConfiguration prepares the runtime inside the caller's transaction.
func (management *Management) publishConfiguration(ctx *gin.Context, store *Store, tenant *tenantRecord, file tenants.FileTenant, record configurationRecord) (PreparedRuntime, error) {
	if tenant.SuspensionPending {
		return nil, failure(409, "suspension_incomplete")
	}
	if len(file.TenantOrigins) == 0 {
		return nil, failure(422, "configuration_incomplete")
	}
	if err := management.checkOrigins(ctx.Request.Context(), store, *tenant, file.TenantOrigins, record.APIBaseURL, record.LocalDevelopment); err != nil {
		return nil, err
	}
	tenant.State = "active"
	tenant.ActiveRevision = &record.Revision
	tenant.Version++
	if err := store.db.Model(&tenantRecord{}).Where("id = ?", tenant.ID).Updates(map[string]any{"state": tenant.State, "active_revision": record.Revision, "version": tenant.Version}).Error; err != nil {
		return nil, err
	}
	config, err := store.RuntimeTenants(ctx.Request.Context())
	if err != nil {
		return nil, failure(422, "runtime_invalid")
	}
	candidate, err := management.build(ctx.Request.Context(), config)
	if err != nil {
		return candidate, failure(422, "runtime_invalid")
	}
	return candidate, nil
}
