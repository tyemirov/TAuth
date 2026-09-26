SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder

.PHONY: ci format lint test-go test-js test-deployment-config-renderer test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

ci: format lint test-go test-js verify-js test-console-browser test-console-pages test-installed-gateway test-deployment-config-renderer test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

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

.PHONY: test-console
test-console:
	$(GO) test ./cmd/server -run '^TestConsole' -count=1
	$(GO) test ./internal/controlplane -count=1

.PHONY: test-database-fixture
test-database-fixture:
	$(GO) test ./cmd/server -run '^TestDatabaseFixture$$' -count=1

.PHONY: test-oauth-metadata
test-oauth-metadata:
	$(GO) test -race ./internal/oauthserver -run 'TestMetadata' -count=1

.PHONY: test-oauth-login test-oauth-login-go test-oauth-login-browser
test-oauth-login: test-oauth-login-go test-oauth-login-browser

test-oauth-login-go:
	$(GO) test ./internal/oauthserver -run '^TestAuthorizationServerBrowserPKCERefreshAndRevocation$$' -count=1

.PHONY: test-oauth-consent
test-oauth-consent:
	$(GO) test -race ./internal/oauthserver -run '^TestOAuthConsent' -count=1

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

.PHONY: test-installed-gateway
test-installed-gateway:
	bash tests/installed-gateway.sh

test-empty-tenant-bootstrap-runtime:
	bash tests/empty-tenant-bootstrap-runtime.sh

test-oauth-provider-bootstrap-runtime:
	bash tests/oauth-provider-bootstrap-runtime.sh

MPRLAB_GATEWAY_EXECUTABLE ?= mprlab-gateway

.PHONY: release publish deploy

release publish deploy:
	@application_root="$$(git rev-parse --show-toplevel)"; \
	if ! command -v "$(MPRLAB_GATEWAY_EXECUTABLE)" >/dev/null 2>&1; then \
		printf 'Gateway runtime is unavailable: %s. Install a released runtime and add its command directory to PATH.\n' \
			"$(MPRLAB_GATEWAY_EXECUTABLE)" >&2; \
		exit 2; \
	fi; \
	exec "$(MPRLAB_GATEWAY_EXECUTABLE)" "app-$@" --app-root "$${application_root}"

.PHONY: test-apple-callback-cors
test-apple-callback-cors:
	$(GO) test ./cmd/server -run '^TestRunServerAppleCallbackCORS$$' -count=1

.PHONY: test-gateway-provisioning
test-gateway-provisioning:
	@test -n "$${TAUTH_GATEWAY_ROOT}" || { echo "TAUTH_GATEWAY_ROOT must select the Gateway checkout"; exit 2; }
	$(GO) test ./cmd/server -run '^TestConsoleActualGatewayClient$$' -count=1 -v

.PHONY: test-console-browser
test-console-browser:
	TAUTH_CONSOLE_BROWSER=1 $(GO) test ./cmd/server -run '^TestConsoleBrowserWorkspace$$' -count=1 -v

.PHONY: format-console test-console-pages
format-console:
	npx --yes prettier@3.6.2 --write web/app/*.js web/app/index.html web/app/workspace.css tests/console-workspace.browser.cjs

test-console-pages:
	bash tests/console-pages.sh

.PHONY: run-tenant-app
run-tenant-app:
	$(GO) run ./examples/tenant-app

.PHONY: test-customer-app
test-customer-app:
	$(GO) test ./internal/customerapp -count=1
