package controlplane

import (
	"errors"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
	"gorm.io/gorm"
)

const OwnerPath = "/api/management/owner-account"
const CSRFHeader = "X-TAuth-CSRF"

// Mount registers owner resources with the reserved console session authority.
func Mount(router *gin.Engine, store *Store, config authkit.ServerConfig, sessions *authkit.OAuthBrowserSessions, users authkit.UserStore, origin string) error {
	validator, err := sessionvalidator.New(sessionvalidator.Config{SigningKey: config.AppJWTSigningKey, Issuer: config.AppJWTIssuer, CookieName: config.SessionCookieName})
	if err != nil {
		return err
	}
	router.GET("/.well-known/tauth-console", func(ctx *gin.Context) {
		ctx.Header("Cache-Control", "no-store")
		ctx.JSON(200, gin.H{"tenant_id": ConsoleTenantID, "google_web_client_id": config.GoogleWebClientID, "console_origin": origin})
	})
	handler := func(ctx *gin.Context) {
		ctx.Header("Cache-Control", "no-store")
		fail := func(status int, code string) {
			ctx.AbortWithStatusJSON(status, gin.H{"code": code, "message": code, "request_id": newID()})
		}
		if ctx.Request.Header.Get("Origin") != origin {
			fail(403, "management.origin_denied")
			return
		}
		if ctx.Request.Method == http.MethodPut && ctx.GetHeader(CSRFHeader) != "1" {
			fail(403, "management.csrf_required")
			return
		}
		if ctx.Request.Method == http.MethodPut && ctx.Request.ContentLength > 0 {
			mediaType, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
			if err != nil || mediaType != "application/json" {
				fail(http.StatusUnsupportedMediaType, "management.media_type_unsupported")
				return
			}
		}
		claims, err := validator.ValidateRequest(ctx.Request)
		if err != nil || claims.TenantID != ConsoleTenantID {
			fail(401, "management.console_session_required")
			return
		}
		_, active, err := sessions.Resolve(ctx.Request, ConsoleTenantID)
		if err != nil {
			fail(500, "management.account_read_failed")
			return
		}
		if !active {
			fail(401, "management.console_session_required")
			return
		}
		if ctx.Request.Method == http.MethodGet || ctx.Request.Method == http.MethodHead {
			owner, err := store.OwnerForSubject(ctx.Request.Context(), claims.Issuer, claims.Subject)
			if errors.Is(err, gorm.ErrRecordNotFound) {
				fail(404, "management.owner_not_found")
				return
			}
			if err != nil {
				fail(500, "management.owner_read_failed")
				return
			}
			ctx.JSON(200, owner)
			return
		}
		email, display, _, _, err := users.GetUserProfile(ctx.Request.Context(), ConsoleTenantID, claims.Subject)
		if err != nil {
			fail(500, "management.profile_read_failed")
			return
		}
		owner, created, err := store.Provision(ctx.Request.Context(), claims.Issuer, claims.Subject, email, display)
		if errors.Is(err, ErrEnrollment) {
			fail(403, "management.enrollment_denied")
			return
		}
		if err != nil {
			fail(500, "management.owner_provision_failed")
			return
		}
		status := 200
		if created {
			status = 201
			ctx.Header("Location", OwnerPath)
		}
		ctx.JSON(status, owner)
	}
	router.GET(OwnerPath, handler)
	router.HEAD(OwnerPath, handler)
	router.PUT(OwnerPath, handler)
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		router.Handle(method, OwnerPath, func(ctx *gin.Context) {
			ctx.Header("Cache-Control", "no-store")
			ctx.Header("Allow", "GET, HEAD, PUT, OPTIONS")
			ctx.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"code": "management.method_not_allowed", "message": "Method is not allowed.", "request_id": newID()})
		})
	}
	return nil
}
