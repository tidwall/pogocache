# ---- build stage ----
FROM golang:1.26.1-alpine AS builder

# Install git so go modules can fetch VCS-based dependencies.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /workspace

# Copy dependency manifests first for better layer-cache utilisation.
COPY go.mod go.sum ./
RUN go mod download

# Copy the full source tree and build the static binary.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o manager \
    ./main.go

# ---- runtime stage ----
# Use distroless for a minimal, CVE-reduced attack surface.
FROM gcr.io/distroless/static:nonroot

WORKDIR /

COPY --from=builder /workspace/manager /manager

# controller-runtime expects USER to be set for leader-election lease ownership.
USER 65532:65532

ENTRYPOINT ["/manager"]
