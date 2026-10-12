# Build stage
FROM golang:1.24-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
# Local shared module is supplied as a named BuildKit context.
COPY --from=shared . /shared

# Use official Go module proxy
ENV GOPROXY="https://proxy.golang.org,direct"

# Download dependencies first (Docker layer cache optimization)
RUN go mod download

# Copy source code (including tracked .pb.go files)
COPY . .

# Ensure all dependencies are consistent
RUN go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev}" \
    -o /app/bin/connection-manager \
    ./cmd/server

# Offline IP geolocation for agent locations: DB-IP "IP to City Lite"
# (CC BY 4.0, https://db-ip.com). Best effort — the image still builds
# without it, and locations then show the address only. The layer is cached;
# pass --build-arg GEOIP_REFRESH=<any new value> (e.g. the month) to refresh,
# or GEOIP_DOWNLOAD=false to skip. EDR_GEOIP_DB can point at another .mmdb
# (e.g. MaxMind GeoLite2-City) mounted into the container.
FROM alpine:3.19 AS geoip
ARG GEOIP_DOWNLOAD=true
ARG GEOIP_REFRESH=initial
RUN mkdir -p /geoip && if [ "$GEOIP_DOWNLOAD" = "true" ]; then       apk add --no-cache curl ca-certificates >/dev/null &&       for m in "$(date -u +%Y-%m)" "$(date -u -d "@$(( $(date +%s) - 2678400 ))" +%Y-%m)"; do         if curl -fsSL --retry 3 --max-time 600 "https://download.db-ip.com/free/dbip-city-lite-${m}.mmdb.gz" -o /tmp/geo.mmdb.gz            && gunzip -c /tmp/geo.mmdb.gz > /geoip/dbip-city-lite.mmdb; then rm -f /tmp/geo.mmdb.gz; echo "GeoIP: dbip-city-lite-${m}"; break; fi;         rm -f /tmp/geo.mmdb.gz /geoip/dbip-city-lite.mmdb;       done;       [ -s /geoip/dbip-city-lite.mmdb ] || echo "WARNING: GeoIP database not downloaded — agent locations disabled";     fi

# Final stage — lightweight runtime
FROM alpine:3.19

# Install CA certificates, timezone data, and openssl (for cert generation fallback)
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user (for future use — currently running as root for PKI writes)
RUN adduser -D -u 1000 edr

# Set working directory
WORKDIR /app

# Create writable certs directory
RUN mkdir -p /app/certs

# Copy binary from builder
COPY --from=builder /app/bin/connection-manager /app/connection-manager

# GeoIP database (may be empty when the download was skipped or failed)
COPY --from=geoip /geoip /app/geoip

# Copy entrypoint script.
# Strip any CRLF introduced by a Windows checkout (git core.autocrlf=true) before
# chmod — a stray \r on the shebang line causes the kernel to try exec'ing
# "/bin/sh\r", which fails with ENOENT and looks like a missing file.
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh \
    && chmod +x /app/docker-entrypoint.sh

# Copy config template
COPY --from=builder /app/config/config.example.yaml /app/config/config.yaml

# NOTE: Running as root to ensure the PKI bootstrap (EnsureFullPKI) can
# always read and write certificate files in the bind-mounted certs directory.
# The bind mount (./connection-manager/certs:/app/certs) may have host-level
# permissions that prevent the 'edr' user (uid 1000) from writing.

# Expose ports
# gRPC port
EXPOSE 50051
# HTTP API/health port
EXPOSE 8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${HTTP_PORT:-8082}/healthz || exit 1

# Set environment variables
ENV LOG_LEVEL=info
ENV GRPC_PORT=50051
ENV HTTP_PORT=8082

# Run via entrypoint (ensures certs dir, then execs the binary)
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["-config", "/app/config/config.yaml"]
