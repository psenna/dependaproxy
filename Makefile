# DependaProxy Makefile.
#
# The host has no Go toolchain, so every Go target runs inside a disposable
# golang container against the rootless DinD daemon (DOCKER_HOST is set in the
# ai-sandbox env). The repo lives under /workspace, which is the only path the
# daemon can see, so we bind-mount the repo directory as /work.
#
# Go build/module/binary caches live in a named Docker volume (not inside the
# repo), so they persist across runs without polluting the working tree (which
# would make gofmt/golangci-lint scan the module-cache testdata).

GOLANG_IMAGE  ?= golang:1.25
POSTGRES_IMAGE ?= postgres:18
MINIO_IMAGE   ?= minio/minio
DOCKER        ?= docker

CURDIR        := $(shell pwd)
GOCACHE_VOL   := dependaproxy-gocache
# go stamps VCS info into binaries by default; git refuses repos owned by another
# uid ("dubious ownership"). Mark /work safe so the container works regardless of
# who owns the checkout (local uid-1000 checkouts, root CI). The DP_TEST_* vars
# are forwarded only when set in the caller's environment (unset -> empty in the
# container -> the postgres/MinIO gated tests skip).
DOCKER_RUN    := $(DOCKER) run --rm -v "$(CURDIR):/work" -w /work \
	-v $(GOCACHE_VOL):/gc \
	-e GOCACHE=/gc/build -e GOMODCACHE=/gc/mod -e GOBIN=/gc/bin \
	-e PATH=/gc/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/work \
	-e DP_TEST_PG_DSN -e DP_TEST_MINIO_ENDPOINT -e DP_TEST_MINIO_ACCESS_KEY -e DP_TEST_MINIO_SECRET_KEY \
	$(GOLANG_IMAGE)
# The race detector needs CGo (it links the race runtime via gcc). The
# golang:1.25 image ships gcc, so enable CGo only for the race test target.
DOCKER_RUN_RACE := $(DOCKER_RUN) -e CGO_ENABLED=1

# Web (Vite + React + TS) targets run inside disposable node/playwright
# containers. npm traffic goes through the DependaProxy registry, which the
# nested DinD daemon reaches via the fixed dependaproxy IP (172.23.0.10).
NODE_IMAGE       ?= node:22-alpine
PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v1.62.1-jammy

DOCKER_RUN_WEB := $(DOCKER) run --rm -v "$(CURDIR):/work" -w /work/web \
	--add-host=dependaproxy:172.23.0.10 \
	-e NPM_CONFIG_REGISTRY=http://dependaproxy:8080/npm \
	-e CI=1 \
	$(NODE_IMAGE)

DOCKER_RUN_E2E := $(DOCKER) run --rm -v "$(CURDIR):/work" -w /work/web \
	--add-host=dependaproxy:172.23.0.10 \
	-e NPM_CONFIG_REGISTRY=http://dependaproxy:8080/npm \
	-e CI=1 \
	$(PLAYWRIGHT_IMAGE)

# Pin tool versions for reproducibility. golangci-lint is installed via
# `go install` so it is built with the project's Go toolchain (a prebuilt
# v2.0.x binary is built with go1.24 and refuses a go1.25 target).
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION   := latest

.PHONY: all test vet fmt-check lint vuln tidy run db stop-db minio stop-minio clean \
	web-install web-build web-unit web-test web-lint web-format web-e2e build-image

all: vet fmt-check test

test:
	$(DOCKER_RUN_RACE) go test -race -p 1 -coverprofile=cover.out ./...

vet:
	$(DOCKER_RUN) go vet ./...

# gofmt only the repo's Go files (not the module cache, which lives in a
# named volume outside the tree, so a plain `gofmt -l .` would also work —
# but the explicit list is unambiguous and matches CI semantics).
fmt-check:
	$(DOCKER_RUN) sh -c 'test -z "$$(gofmt -l .)" || { echo "gofmt drift:"; gofmt -l .; exit 1; }'

tidy:
	$(DOCKER_RUN) go mod tidy

# Installs golangci-lint into the mounted cache (built with the project's Go)
# and runs it.
lint:
	$(DOCKER_RUN) sh -c '\
		test -x $$GOBIN/golangci-lint || \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
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

# Stand up a MinIO server for the S3-cache integration tests. The tests read
# DP_TEST_MINIO_ENDPOINT / DP_TEST_MINIO_ACCESS_KEY / DP_TEST_MINIO_SECRET_KEY
# and skip when the endpoint is unset — point them at this server (the root
# credentials are the MINIO_ROOT_USER / MINIO_ROOT_PASSWORD below):
#   make minio
#   DP_TEST_MINIO_ENDPOINT=<minio-ip>:9000 DP_TEST_MINIO_ACCESS_KEY=dependaproxy \
#     DP_TEST_MINIO_SECRET_KEY=changeme go test ./...
minio:
	$(DOCKER) rm -f dependaproxy-minio 2>/dev/null || true
	$(DOCKER) run -d --name dependaproxy-minio \
		-e MINIO_ROOT_USER=dependaproxy \
		-e MINIO_ROOT_PASSWORD=changeme \
		-p 9000:9000 $(MINIO_IMAGE) server /data --console-address ":9001"

stop-minio:
	$(DOCKER) rm -f dependaproxy-minio

clean:
	rm -rf cover.out cover.html

# --- web/ (Vite + React + TS scaffold, issue #140) ---
web-install:
	$(DOCKER_RUN_WEB) npm ci

# Self-contained: installs deps then builds, so it works on a clean checkout.
web-build:
	$(DOCKER_RUN_WEB) sh -c 'npm ci && npm run build'

web-unit:
	$(DOCKER_RUN_WEB) npm test

# Full web gate: lint + unit + e2e.
web-test: web-lint web-unit web-e2e

web-lint:
	$(DOCKER_RUN_WEB) npm run lint

web-format:
	$(DOCKER_RUN_WEB) npm run format

web-e2e:
	$(DOCKER_RUN_E2E) sh -c 'npx playwright install chromium && npm run e2e'

# Build the full Docker image (web-build first so web/dist exists locally too;
# the Dockerfile's web-build stage re-runs the web build for the embed in #152).
build-image: web-build
	$(DOCKER) build -t dependaproxy:dev .