package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tyemirov/tauth/internal/authkit"
	"gorm.io/gorm"
)

// AddressResolver resolves the external destination before a bounded probe.
type AddressResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// ContextDialer connects only to the address pinned by the checker.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// SetupNetwork contains the DNS, connection, and TLS boundaries.
type SetupNetwork struct {
	Resolver AddressResolver
	Dialer   ContextDialer
	TLS      *tls.Config
}

// DefaultSetupNetwork uses public DNS and the system TLS trust roots.
func DefaultSetupNetwork() SetupNetwork {
	return SetupNetwork{Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: 3 * time.Second}, TLS: &tls.Config{MinVersion: tls.VersionTLS12}}
}

// SetupChecker verifies the fixed customer API protocol without owner credentials.
type SetupChecker struct {
	nonces  authkit.NonceStore
	network SetupNetwork
}

// NewSetupChecker binds the customer probe to the service nonce store.
func NewSetupChecker(nonces authkit.NonceStore, network SetupNetwork) *SetupChecker {
	return &SetupChecker{nonces: nonces, network: network}
}

type setupEvidence struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Code   string `json:"code"`
}
type setupCheck struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Revision  int64           `json:"revision"`
	State     string          `json:"state"`
	CreatedAt time.Time       `json:"created_at"`
	Evidence  []setupEvidence `json:"evidence" gorm:"serializer:json"`
}

func (setupCheck) TableName() string { return "tenant_setup_checks" }

var publicIPv6Range = netip.MustParsePrefix("2000::/3")

var deniedPublicRanges = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16")}

func publicDestination(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if address.Is6() && !publicIPv6Range.Contains(address) {
		return false
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range deniedPublicRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
func (checker *SetupChecker) check(ctx context.Context, origin, frontend, tenantID string) []setupEvidence {
	fail := func(path, code string, status int) []setupEvidence {
		return []setupEvidence{{Path: path, Code: code, Status: status}}
	}
	target, err := url.Parse(origin)
	if err != nil || target.Scheme != "https" {
		return fail("", "https_required", 0)
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := checker.network.Resolver.LookupIPAddr(deadline, target.Hostname())
	if err != nil || len(addresses) == 0 {
		return fail("", "dns_unavailable", 0)
	}
	for _, address := range addresses {
		if !publicDestination(address.IP) {
			return fail("", "destination_denied", 0)
		}
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	pinned := net.JoinHostPort(addresses[0].IP.String(), port)
	transport := &http.Transport{TLSClientConfig: checker.network.TLS.Clone(), DisableKeepAlives: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return checker.network.Dialer.DialContext(ctx, network, pinned)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	evidence := []setupEvidence{}
	for _, step := range []struct {
		path, method string
		status       int
	}{{"/auth/nonce", "POST", 200}, {"/me", "GET", 401}, {"/private", "GET", 401}} {
		request, err := http.NewRequestWithContext(deadline, step.method, origin+step.path, strings.NewReader("{}"))
		if err != nil {
			return fail(step.path, "request_invalid", 0)
		}
		request.Header.Set("Origin", frontend)
		request.Header.Set("X-TAuth-Tenant", tenantID)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return fail(step.path, "destination_unavailable", 0)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 {
			return fail(step.path, "response_invalid", response.StatusCode)
		}
		if response.StatusCode != step.status {
			return fail(step.path, "status_mismatch", response.StatusCode)
		}
		if response.Header.Get("Access-Control-Allow-Origin") != frontend || response.Header.Get("Access-Control-Allow-Credentials") != "true" {
			return fail(step.path, "cors_mismatch", response.StatusCode)
		}
		if step.path == "/auth/nonce" {
			var body struct {
				Nonce string `json:"nonce"`
			}
			if err := json.Unmarshal(data, &body); err != nil || body.Nonce == "" {
				return fail(step.path, "nonce_invalid", response.StatusCode)
			}
			if err := checker.nonces.Consume(deadline, tenantID, body.Nonce); err != nil {
				return fail(step.path, "tenant_binding_invalid", response.StatusCode)
			}
		}
		evidence = append(evidence, setupEvidence{Path: step.path, Status: response.StatusCode, Code: "passed"})
	}
	return evidence
}
func (management *Management) setupCheck(ctx *gin.Context, owner string, id string) {
	data, err := readManagementBody(ctx)
	if err != nil {
		respondError(ctx, err)
		return
	}
	var input struct {
		Revision int64 `json:"revision"`
	}
	if err := decodeBody(data, &input); err != nil {
		respondError(ctx, err)
		return
	}
	key := ctx.GetHeader("Idempotency-Key")
	if len(key) < 1 || len(key) > 128 {
		respondError(ctx, failure(400, "idempotency_key_required"))
		return
	}
	canonical, _ := json.Marshal(input)
	digest := management.store.digest(append(canonical, []byte(ctx.GetHeader("If-Match"))...))
	management.mutation.Lock()
	defer management.mutation.Unlock()
	store := management.store
	var receipt receiptRecord
	err = store.db.WithContext(ctx.Request.Context()).First(&receipt, "owner_account_id = ? AND path = ? AND key = ?", owner, ctx.Request.URL.Path, key).Error
	if err == nil {
		if receipt.Digest != digest {
			respondError(ctx, failure(409, "idempotency_conflict"))
			return
		}
		respond(ctx, resourceResult{Status: receipt.Status, Body: json.RawMessage(receipt.Response), Location: receipt.Location})
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		respondError(ctx, err)
		return
	}
	_, file, config, err := store.activeConfiguration(ctx.Request.Context(), owner, id)
	if err != nil {
		respondError(ctx, err)
		return
	}
	if err := requireMatch(ctx.GetHeader("If-Match"), configETag(config.Revision)); err != nil {
		respondError(ctx, err)
		return
	}
	if input.Revision != config.Revision {
		respondError(ctx, failure(412, "revision_conflict"))
		return
	}
	if config.APIBaseURL == "" || config.LocalDevelopment {
		respondError(ctx, failure(422, "verified_https_destination_required"))
		return
	}
	var recent int64
	if err := store.db.WithContext(ctx.Request.Context()).Model(&auditEvent{}).Where("actor_account_id = ? AND created_at > ?", owner, management.now().UTC().Add(-time.Minute)).Count(&recent).Error; err != nil {
		respondError(ctx, err)
		return
	}
	if recent >= 60 {
		respondError(ctx, failure(429, "mutation_rate_exceeded"))
		return
	}
	result := setupCheck{ID: newID(), TenantID: id, Revision: config.Revision, CreatedAt: management.now().UTC(), State: "succeeded", Evidence: management.integration.checker.check(ctx.Request.Context(), config.APIBaseURL, file.TenantOrigins[0], id)}
	for _, item := range result.Evidence {
		if item.Code != "passed" {
			result.State = "failed"
		}
	}
	location := TenantsPath + "/" + id + "/setup-checks/" + result.ID
	err = store.db.WithContext(ctx.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&result).Error; err != nil {
			return err
		}
		if err := store.local(tx).audit(ctx.Request.Context(), owner, id, "setup.checked", result.State, config.Revision); err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return tx.Create(&receiptRecord{OwnerAccountID: owner, Path: ctx.Request.URL.Path, Key: key, Digest: digest, Response: string(encoded), Status: 201, Location: location}).Error
	})
	if err != nil {
		respondError(ctx, err)
		return
	}
	respond(ctx, resourceResult{Status: 201, Body: result, Location: location})
}
