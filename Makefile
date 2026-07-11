SHELL := /bin/bash

GO ?= go
STATICCHECK ?= staticcheck
INEFFASSIGN ?= ineffassign
GO_TAGS ?= nodynamic,webp_encoder
DOCKER_IMAGE ?= ghcr.io/tyemirov/tauth
PUBLISH_PLATFORMS ?= linux/amd64,linux/arm64
PUBLISH_BRANCH ?= master
PUBLISH_REMOTE ?= origin
PUBLISH_RELEASE_ARGS ?=
RELEASE_ARGS ?=
RELEASE_HELPER := $(abspath $(CURDIR)/scripts/release/release_helper.py)
RELEASE_ARTIFACT_TARGETS ?= container-artifacts
RELEASE_TOOL_DIR := $(abspath $(CURDIR)/scripts/release)
DEPLOY_ARGS ?=
GATEWAY_DIR ?=

.PHONY: ci format lint test-go test-js release container-artifacts publish-release publish deploy

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
	@RELEASE_HELPER="$(RELEASE_HELPER)" RELEASE_ARTIFACT_TARGETS="$(RELEASE_ARTIFACT_TARGETS)" bash scripts/release.sh $(RELEASE_ARGS)

container-artifacts:
	@"$(RELEASE_TOOL_DIR)/prepare_container_artifact.sh" --name tauth --image "$(DOCKER_IMAGE)" --file Dockerfile --context . --platforms "$(PUBLISH_PLATFORMS)"

publish-release:
	@RELEASE_HELPER="$(RELEASE_HELPER)" bash scripts/publish-release.sh $(PUBLISH_RELEASE_ARGS)

publish: publish-release
	@"$(RELEASE_TOOL_DIR)/publish_container_artifacts.sh"

deploy:
	@GATEWAY_DIR="$(GATEWAY_DIR)" DOCKER_IMAGE="$(DOCKER_IMAGE)" bash scripts/deploy.sh $(DEPLOY_ARGS)
