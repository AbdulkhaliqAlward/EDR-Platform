# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for go modules
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
# Local shared module is supplied as a named BuildKit context.
COPY --from=shared . /shared

# Speed up module downloads
ENV GOPROXY="https://proxy.golang.org,direct"

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -o sigma-engine ./cmd/sigma-engine-kafka/main.go

# Final stage
FROM alpine:3.19

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/sigma-engine .

# Copy config
COPY --from=builder /app/config ./config/

# Copy migrations
COPY internal/infrastructure/database/migrations ./migrations/

# Copy rules into container for auto-seeding
COPY sigma_rules/rules/ ./rules/

# Create non-root user and give ownership of /app
RUN adduser -D -g '' appuser && chown -R appuser:appuser /app
USER appuser

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the binary
ENTRYPOINT ["./sigma-engine"]
CMD ["-workers", "4"]
