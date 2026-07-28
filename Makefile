# DependaProxy Makefile.
#
# The host has no Go toolchain, so every Go target runs inside a disposable
# golang container against the rootless DinD daemon (DOCKER_HOST is set in the
# ai-sandbox env). The repo lives under /workspace, which is the only path the
# daemon can see, so we bind-mount the repo directory as /work and put the Go
# build/module caches under .gocache/ (gitignored) so they persist across runs.

GOLANG_IMAGE  ?= golang:1.25
POSTGRES_IMAGE ?= postgres:18
DOCKER        ?= docker

CURDIR        := $(shell pwd)
CACHE         := $(CURDIR)/.gocache
DOCKER_RUN    := $(DOCKER) run --rm -v "$(CURDIR):/work" -w /work \
	-e GOCACHE=$(CACHE)/build -e GOMODCACHE=$(CACHE)/mod -e GOBIN=$(CACHE)/bin \
	-e PATH=$(CACHE)/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	$(GOLANG_IMAGE)
# The race detector needs CGo (it links the race runtime via gcc). The
# golang:1.25 image ships gcc, so enable CGo only for the race test target.
DOCKER_RUN_RACE := $(DOCKER_RUN) -e CGO_ENABLED=1

# Pin tool versions for reproducibility.
GOLANGCI_LINT_VERSION := v2.0.2
GOVULNCHECK_VERSION   := latest

.PHONY: all test vet fmt-check lint vuln tidy run db stop-db clean

all: vet fmt-check test

test:
	$(DOCKER_RUN_RACE) go test -race -coverprofile=cover.out ./...

vet:
	$(DOCKER_RUN) go vet ./...

fmt-check:
	$(DOCKER_RUN) sh -c 'test -z "$$(gofmt -l .)" || { echo "gofmt drift:"; gofmt -l .; exit 1; }'

tidy:
	$(DOCKER_RUN) go mod tidy

# Installs golangci-lint into the mounted cache and runs it.
lint:
	$(DOCKER_RUN) sh -c '\
		test -x $$GOBIN/golangci-lint || \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $$GOBIN $(GOLANGCI_LINT_VERSION); \
		golangci-lint run ./...'

# Installs govulncheck into the mounted cache and runs it.
vuln:
	$(DOCKER_RUN) sh -c '\
		test -x $$GOBIN/govulncheck || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION); \
		govulncheck ./...'

run:
	$(DOCKER_RUN) go run ./cmd/dependaproxy

# Stand up a PostgreSQL 18 service for local dev/tests.
db:
	$(DOCKER) rm -f dependaproxy-pg 2>/dev/null || true
	$(DOCKER) run -d --name dependaproxy-pg \
		-e POSTGRES_PASSWORD=secret -e POSTGRES_DB=dependaproxy \
		-p 5432:5432 $(POSTGRES_IMAGE)

stop-db:
	$(DOCKER) rm -f dependaproxy-pg

clean:
	rm -rf .gocache cover.out cover.html