SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder

.PHONY: ci format lint test-go test-js test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

ci: format lint test-go test-js test-empty-tenant-bootstrap-runtime test-oauth-provider-bootstrap-runtime

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

test-js:
	npm test

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
