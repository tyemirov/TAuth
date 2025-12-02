SHELL := /bin/bash

.PHONY: ci format lint test-go test-js

ci: format lint test-go test-js

format:
	go fmt ./...

lint:
	go vet ./...

test-go:
	go test ./...

test-js:
	npm test
