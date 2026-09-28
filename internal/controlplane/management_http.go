package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"github.com/tyemirov/tauth/pkg/sessionvalidator"
	"gorm.io/gorm"
)

type resourceResult struct {
	Status         int
	Body           any
	ReceiptBody    any
	Location, ETag string
}
type receiptRecord struct {
	OwnerAccountID, Path, Key, Digest, Response string
	Status                                      int
	Location                                    string
}

func (receiptRecord) TableName() string { return "management_receipts" }
func respond(ctx *gin.Context, result resourceResult) {
	if result.Location != "" {
		ctx.Header("Location", result.Location)
	}
	if result.ETag != "" {
		ctx.Header("ETag", result.ETag)
	}
	ctx.JSON(result.Status, result.Body)
}
func respondError(ctx *gin.Context, err error) {
	typed := &apiError{Status: 500, Code: "management.storage_failed"}
	var expected *apiError
	if errors.As(err, &expected) {
		typed = expected
	}
	ctx.AbortWithStatusJSON(typed.Status, gin.H{"code": typed.Code, "message": strings.ReplaceAll(strings.TrimPrefix(typed.Code, "management."), "_", " "), "details": typed.Details, "request_id": newID()})
}
func decodeBody(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return failure(400, "body_invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return failure(400, "body_invalid")
	}
	return nil
}
func pageQuery(ctx *gin.Context) (int, string, error) {
	limit := 50
	if raw, ok := ctx.GetQuery("limit"); ok {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, "", failure(400, "page_invalid")
		}
		limit = parsed
	}
	cursor := ctx.Query("cursor")
	if len(cursor) > 128 {
		return 0, "", failure(400, "cursor_invalid")
	}
	for key := range ctx.Request.URL.Query() {
		if key != "limit" && key != "cursor" && !(key == "app_id" && ctx.Request.URL.Path == TenantsPath) {
			return 0, "", failure(400, "query_invalid")
		}
	}
	return limit, cursor, nil
}
func (management *Management) Mount(router *gin.Engine, config authkit.ServerConfig, sessions *authkit.OAuthBrowserSessions, origin string) error {
	validator, err := sessionvalidator.New(sessionvalidator.Config{SigningKey: config.AppJWTSigningKey, Issuer: config.AppJWTIssuer, CookieName: config.SessionCookieName})
	if err != nil {
		return err
	}
	handler := func(ctx *gin.Context) {
		ctx.Header("Cache-Control", "no-store")

		mutation := ctx.Request.Method != "GET" && ctx.Request.Method != "HEAD" && ctx.Request.Method != "OPTIONS"
		var owner Owner
		if authorization := ctx.GetHeader("Authorization"); authorization != "" {
			if ctx.GetHeader("Origin") != "" || ctx.GetHeader("Cookie") != "" {
				respondError(ctx, failure(403, "provisioning_browser_denied"))
				return
			}
			credential, err := management.store.credential(ctx.Request.Context(), authorization)
			if err != nil {
				respondError(ctx, err)
				return
			}
			owner = Owner{ID: credential.OwnerAccountID}
			ctx.Set(principalContextKey, &credential)
		} else {
			if ctx.GetHeader("Origin") != origin {
				respondError(ctx, failure(403, "origin_denied"))
				return
			}
			if mutation && ctx.GetHeader(CSRFHeader) != "1" {
				respondError(ctx, failure(403, "csrf_required"))
				return
			}
			claims, err := validator.ValidateRequest(ctx.Request)
			if err != nil || claims.TenantID != ConsoleTenantID {
				respondError(ctx, failure(401, "console_session_required"))
				return
			}
			_, active, err := sessions.Resolve(ctx.Request, ConsoleTenantID)
			if err != nil {
				respondError(ctx, err)
				return
			}
			if !active {
				respondError(ctx, failure(401, "console_session_required"))
				return
			}
			owner, err = management.store.OwnerForSubject(ctx.Request.Context(), claims.Issuer, claims.Subject)
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = failure(404, "owner_not_found")
			}
			if err != nil {
				respondError(ctx, err)
				return
			}

		}
		if strings.HasPrefix(ctx.Request.URL.Path, CredentialsPath) {
			if provisioningPrincipal(ctx) != nil {
				respondError(ctx, failure(403, "operation_denied"))
				return
			}
			management.credentials(ctx, owner)
			return
		}
		root := TenantsPath
		apps := ctx.Request.URL.Path == AppsPath || strings.HasPrefix(ctx.Request.URL.Path, AppsPath+"/")
		if apps {
			root = AppsPath
			if provisioningPrincipal(ctx) != nil {
				respondError(ctx, failure(403, "operation_denied"))
				return
			}
		}
		path := strings.TrimPrefix(ctx.Request.URL.Path, root)
		parts := []string{}
		if path != "" {
			parts = strings.Split(strings.TrimPrefix(path, "/"), "/")
		}
		if principal := provisioningPrincipal(ctx); principal != nil {
			if err := authorizeProvisioning(principal, ctx.Request.Method, parts); err != nil {
				respondError(ctx, err)
				return
			}
		}
		if !apps && len(parts) > 0 {
			if _, err := management.store.tenant(ctx.Request.Context(), owner.ID, parts[0]); err != nil {
				respondError(ctx, err)
				return
			}
		}
		if len(parts) > 1 && (parts[1] == "reauthentications" || parts[1] == "key-exports") && provisioningPrincipal(ctx) != nil {
			respondError(ctx, failure(403, "operation_denied"))
			return
		}
		if apps && len(parts) > 1 {
			respondError(ctx, failure(404, "resource_not_found"))
			return
		}
		methods := ""
		switch {
		case len(parts) == 2 && parts[1] == "setup-checks":
			methods = "GET, HEAD, POST, OPTIONS"
		case len(parts) == 3 && parts[1] == "setup-checks":
			methods = "GET, HEAD, OPTIONS"
		case len(parts) == 2 && parts[1] == "integration":
			methods = "GET, HEAD, OPTIONS"
		case len(parts) == 2 && (parts[1] == "reauthentications" || parts[1] == "key-exports"):
			methods = "POST, OPTIONS"
		case len(parts) == 3 && (parts[1] == "reauthentications" || parts[1] == "key-exports"):
			methods = "GET, HEAD, OPTIONS"
		case len(parts) == 0:
			methods = "GET, HEAD, POST, OPTIONS"
		case len(parts) == 1:
			methods = "GET, HEAD, PATCH, OPTIONS"
		case len(parts) == 2 && parts[1] == "configuration":
			methods = "GET, HEAD, PUT, OPTIONS"
		case len(parts) == 2 && (parts[1] == "origin-proofs" || parts[1] == "activations"):
			methods = "GET, HEAD, POST, OPTIONS"
		case len(parts) == 2 && parts[1] == "audit-events" || len(parts) == 3 && (parts[1] == "activations" || parts[1] == "origin-proofs") || len(parts) == 5 && parts[1] == "origin-proofs" && parts[3] == "verifications":
			methods = "GET, HEAD, OPTIONS"
		case len(parts) == 4 && parts[1] == "origin-proofs" && parts[3] == "verifications":
			methods = "POST, OPTIONS"
		default:
			respondError(ctx, failure(404, "resource_not_found"))
			return
		}
		ctx.Header("Allow", methods)
		if ctx.Request.Method == "OPTIONS" {
			ctx.Status(204)
			return
		}
		if !strings.Contains(", "+methods+",", ", "+ctx.Request.Method+",") {
			respondError(ctx, failure(405, "method_not_allowed"))
			return
		}
		if mutation && len(parts) == 2 && parts[1] == "setup-checks" {
			management.setupCheck(ctx, owner.ID, parts[0])
			return
		}
		if !mutation {
			var result resourceResult
			var err error
			if apps {
				result, err = management.readApps(ctx, owner.ID, parts)
			} else {
				result, err = management.read(ctx, owner.ID, parts)
			}
			if err != nil {
				respondError(ctx, err)
			} else {
				respond(ctx, result)
			}
			return
		}
		data, err := readManagementBody(ctx)
		if err != nil {
			respondError(ctx, err)
			return
		}
		management.mutation.Lock()
		defer management.mutation.Unlock()
		var result resourceResult
		var prepared PreparedRuntime
		var suspended string
		err = management.store.db.WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
			// The singleton row also serializes writers outside this HTTP process.
			if err := tx.Model(&consoleBootstrap{}).Where("id = ?", ConsoleTenantID).Update("id", ConsoleTenantID).Error; err != nil {
				return err
			}
			store := management.store.local(tx)
			if principal := provisioningPrincipal(ctx); principal != nil {
				current, err := store.credential(ctx.Request.Context(), ctx.GetHeader("Authorization"))
				if err != nil {
					return err
				}
				if err := authorizeProvisioning(&current, ctx.Request.Method, parts); err != nil {
					return err
				}
				ctx.Set(principalContextKey, &current)
			}
			var digest, key string
			// Canonical JSON gives equivalent object field order the same retry identity.
			var payload any
			if err := json.Unmarshal(data, &payload); err != nil {
				return failure(400, "body_invalid")
			}
			canonical, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if ctx.Request.Method == "POST" {
				key = ctx.GetHeader("Idempotency-Key")
				if len(key) < 1 || len(key) > 128 {
					return failure(400, "idempotency_key_required")
				}
				mac := hmac.New(sha256.New, store.digestKey)
				_, _ = mac.Write(canonical)
				_, _ = mac.Write([]byte(ctx.GetHeader("If-Match")))
				digest = hex.EncodeToString(mac.Sum(nil))
				var receipt receiptRecord
				err := tx.First(&receipt, "owner_account_id = ? AND path = ? AND key = ?", owner.ID, ctx.Request.URL.Path, key).Error
				if err == nil {
					if receipt.Digest != digest {
						return failure(409, "idempotency_conflict")
					}
					result = resourceResult{Status: receipt.Status, Location: receipt.Location, Body: json.RawMessage(receipt.Response)}
					return nil
				}
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
			}
			var recent int64
			if err := tx.Model(&auditEvent{}).Where("actor_account_id = ? AND created_at > ?", owner.ID, management.now().UTC().Add(-time.Minute)).Count(&recent).Error; err != nil {
				return err
			}
			if recent >= 60 {
				return failure(429, "mutation_rate_exceeded")
			}
			if apps {
				result, err = management.writeApp(ctx, store, owner.ID, parts, data)
			} else {
				result, prepared, suspended, err = management.write(ctx, store, owner.ID, parts, data)
			}
			if err != nil {
				return err
			}
			if key != "" {
				receiptBody := result.Body
				if result.ReceiptBody != nil {
					receiptBody = result.ReceiptBody
				}
				encoded, err := json.Marshal(receiptBody)
				if err != nil {
					return err
				}
				return tx.Create(&receiptRecord{OwnerAccountID: owner.ID, Path: ctx.Request.URL.Path, Key: key, Digest: digest, Response: string(encoded), Status: result.Status, Location: result.Location}).Error
			}
			return nil
		})
		if err != nil {
			if prepared != nil {
				prepared.Discard()
			}
			respondError(ctx, err)
			return
		}
		if prepared != nil {
			prepared.Publish()
		}
		if suspended != "" {
			if err := prepared.Drain(ctx.Request.Context()); err != nil {
				respondError(ctx, failure(503, "suspension_incomplete"))
				return
			}
			if err := management.store.RevokeSuspended(ctx.Request.Context(), suspended); err != nil {
				respondError(ctx, err)
				return
			}
		}
		respond(ctx, result)
	}
	router.Any(CredentialsPath, handler)
	router.Any(CredentialsPath+"/*credential", handler)
	router.Any(AppsPath, handler)
	router.Any(AppsPath+"/*app", handler)
	router.Any(TenantsPath, handler)
	router.Any(TenantsPath+"/*resource", handler)
	return nil
}

func readManagementBody(ctx *gin.Context) ([]byte, error) {
	media, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, failure(415, "media_type_unsupported")
	}
	data, err := io.ReadAll(http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 32768))
	if err != nil {
		return nil, failure(413, "body_too_large")
	}
	return data, nil
}
