# DependaProxy — multi-stage, static, CGo-free build.
#
# Stage 1: build the binary with the pinned Go toolchain.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w" -o /out/dependaproxy ./cmd/dependaproxy

# Stage 2: minimal runtime. scratch has no CA roots, so the outbound HTTPS calls
# to npmjs.org / pypi.org upstreams need the CA bundle copied from the builder.
FROM scratch
COPY --from=build /out/dependaproxy /dependaproxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY config.example.yaml /config.example.yaml

USER 65532
EXPOSE 8080
ENTRYPOINT ["/dependaproxy"]
# The operator mounts a real config (with its Postgres backend) at /config.yaml.
CMD ["-config", "/config.yaml"]