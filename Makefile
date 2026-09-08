SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder

.PHONY: ci format lint test-go test-js test-deployment-config-renderer test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

ci: format lint test-go test-js test-deployment-config-renderer test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

format:
	$(GO) fmt ./...

lint:
	@command -v $(STATICCHECK) >/dev/null 2>&1 || { echo 'staticcheck is required (install via `go install honnef.co/go/tools/cmd/staticcheck@latest`)'; exit 1; }
	@command -v $(INEFFASSIGN) >/dev/null 2>&1 || { echo 'ineffassign is required (install via `go install github.com/gordonklaus/ineffassign@latest`)'; exit 1; }
	$(GO) vet -tags $(GO_TAGS) ./...
	$(STATICCHECK) -tags $(GO_TAGS) ./...
	$(INEFFASSIGN) ./...

test-go:
	$(GO) test ./...

.PHONY: test-oauth-metadata
test-oauth-metadata:
	$(GO) test -race ./internal/oauthserver -run 'TestMetadata' -count=1

.PHONY: test-oauth-login test-oauth-login-go test-oauth-login-browser
test-oauth-login: test-oauth-login-go test-oauth-login-browser

test-oauth-login-go:
	$(GO) test ./internal/oauthserver -run '^TestAuthorizationServerBrowserPKCERefreshAndRevocation$$' -count=1

test-oauth-login-browser:
	node --test tests/oauth-authorization.browser.test.js

.PHONY: test-github-http test-github-config test-github-oauth test-github-browser

test-github-http:
	$(GO) test -race ./internal/authkit -run GitHub -count=1

test-github-config:
	$(GO) test ./internal/tenants ./internal/appconfig ./internal/doctor ./internal/preflight ./internal/deploymentconfig ./cmd/server -run GitHub -count=1

test-github-oauth:
	$(GO) test ./internal/oauthserver ./pkg/oauthvalidator -run GitHub -count=1

test-github-browser:
	node --test tests/github*.test.js

.PHONY: test-github-browser-server test-github-oauth-browser-server
test-github-oauth-browser-server:
	$(GO) test ./internal/oauthserver -run '^TestGitHubOAuthBrowserFixture$$' -count=1 -timeout=5m -v

test-github-browser-server:
	$(GO) test ./internal/authkit -run '^TestGitHubBrowserFixture$$' -count=1 -timeout=5m -v

test-js:
	npm test

.PHONY: verify-js
verify-js:
	npm run verify

test-deployment-config-renderer:
	bash tests/deployment-config-renderer.sh

test-empty-tenant-bootstrap-runtime:
	bash tests/empty-tenant-bootstrap-runtime.sh

test-oauth-provider-bootstrap-runtime:
	bash tests/oauth-provider-bootstrap-runtime.sh

.PHONY: release publish deploy

release publish deploy:
	@application_root="$$(git rev-parse --show-toplevel)"; \
	gateway_root="$$(dirname "$${application_root}")/mprlab-gateway"; \
	if [ ! -d "$${gateway_root}" ]; then \
		printf "required sibling gateway is missing: %s; clone mprlab-gateway at exactly %s\n" \
			"$${gateway_root}" "$${gateway_root}" >&2; \
		exit 2; \
	fi; \
	$(MAKE) --no-print-directory -C "$${gateway_root}" "app-$@" \
		MPRLAB_APP_ROOT="$${application_root}"
