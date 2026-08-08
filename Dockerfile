# DependaProxy — multi-stage, static, CGo-free build.
#
# Stage 1: build the binary with the pinned Go toolchain.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w" -o /out/dependaproxy ./cmd/dependaproxy

# Stage 2: build the GuardDog venv. The guarddog-scan middleware shells out to
# the `guarddog` CLI, so the runtime image ships a Python runtime + this venv.
# The version pin IS the malware-DB version: bumping it updates the malware
# rules (see README "guarddog-scan").
FROM python:3.13-slim AS guarddog-builder
RUN python -m venv /opt/guarddog-venv
ENV PATH="/opt/guarddog-venv/bin:$PATH"
RUN pip install --no-cache-dir guarddog==3.1.0

# Stage 3: runtime. scratch has no CA roots, so the outbound HTTPS calls to
# npmjs.org / pypi.org upstreams need the CA bundle copied from the builder.
FROM python:3.13-slim
COPY --from=build /out/dependaproxy /dependaproxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=guarddog-builder /opt/guarddog-venv /opt/guarddog-venv
ENV PATH="/opt/guarddog-venv/bin:$PATH"
# GuardDog writes some resource files (e.g. top_npm_packages.json) inside its
# own site-packages at runtime; the runtime user (65532) must own the venv.
RUN chown -R 65532:65532 /opt/guarddog-venv
COPY config.example.yaml /config.example.yaml

USER 65532
EXPOSE 8080
ENTRYPOINT ["/dependaproxy"]
# The operator mounts a real config (with its Postgres backend) at /config.yaml.
CMD ["-config", "/config.yaml"]
