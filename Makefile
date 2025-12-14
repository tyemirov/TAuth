SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder

.PHONY: ci format lint test-go test-js

ci: format lint test-go test-js

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
