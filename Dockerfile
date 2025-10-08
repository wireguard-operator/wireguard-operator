# Build arguments
ARG GO_VERSION=1.24
ARG TARGETOS=linux
ARG TARGETARCH

# Version and build information injected via build args
ARG REGISTRY_AND_USERNAME
ARG NAME
ARG TAG
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_TIME
ARG BRANCH
ARG GO_BUILDFLAGS
ARG GO_LDFLAGS

# Build stage with caching
FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION} AS builder

# Set up Go environment
ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org
ENV GOCACHE=/root/.cache/go-build
ENV GOMODCACHE=/root/.cache/go-mod

WORKDIR /workspace

RUN apt-get update && apt-get install -y libcap2-bin

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
# Download and verify dependencies with cache mount
RUN --mount=type=cache,target=/root/.cache/go-mod \
    go mod download && \
    go mod verify

# Copy the go source
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
ARG GO_BUILDFLAGS
ARG GO_LDFLAGS

# Build the binary with cache mount
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/.cache/go-mod \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build ${GO_BUILDFLAGS} \
    -ldflags "${GO_LDFLAGS}" \
    -o manager cmd/main.go \
    && cp manager operator \
    && cp manager controller \
    && setcap 'cap_net_admin,cap_net_raw=+ep' controller

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot AS base

ARG VERSION
ARG GIT_COMMIT
ARG BUILD_TIME

LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

WORKDIR /
USER 65534:65534

FROM base AS operator
LABEL org.opencontainers.image.source="https://github.com/wireguard-operator/operator"
COPY --from=builder --chmod=555 --chown=65534:65534 /workspace/operator .
ENTRYPOINT ["/operator"]

FROM base AS controller
LABEL org.opencontainers.image.source="https://github.com/wireguard-operator/controller"
COPY --from=builder --chmod=555 --chown=65534:65534 /workspace/controller .
ENTRYPOINT ["/controller"]
