package authkit

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/tenants"
)

func resolveTenantID(context *gin.Context, fallbackTenantID string) string {
	if context != nil {
		if tenant, ok := tenants.TenantFromContext(context); ok {
			id := strings.TrimSpace(string(tenant.ID()))
			if id != "" {
				return id
			}
		}
	}
	return fallbackTenantID
}
