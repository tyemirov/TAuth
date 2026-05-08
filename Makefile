SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder
DOCKER_IMAGE ?= ghcr.io/tyemirov/tauth
PUBLISH_PLATFORMS ?= linux/amd64,linux/arm64
PUBLISH_BRANCH ?= master
PUBLISH_REMOTE ?= origin
PUBLISH_ARGS ?=
RELEASE_ARGS ?=
RELEASE_HELPER ?=
DEPLOY_ARGS ?=
GATEWAY_DIR ?=

.PHONY: ci format lint test-go test-js release publish deploy

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

release:
	@RELEASE_HELPER="$(RELEASE_HELPER)" bash scripts/release.sh $(RELEASE_ARGS)

publish:
	@DOCKER_IMAGE="$(DOCKER_IMAGE)" PUBLISH_PLATFORMS="$(PUBLISH_PLATFORMS)" PUBLISH_BRANCH="$(PUBLISH_BRANCH)" PUBLISH_REMOTE="$(PUBLISH_REMOTE)" bash scripts/publish.sh $(PUBLISH_ARGS)

deploy:
	@GATEWAY_DIR="$(GATEWAY_DIR)" DOCKER_IMAGE="$(DOCKER_IMAGE)" bash scripts/deploy.sh $(DEPLOY_ARGS)
