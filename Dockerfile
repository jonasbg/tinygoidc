# Multi-stage Dockerfile for gotiny-oidc
# Build stage: compile a static Linux binary
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git build-base ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Ensure CGO is disabled for a fully static binary
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -ldflags='-s -w' -o /out/gotiny-oidc ./

# Final stage: minimal image
FROM scratch

# Add CA certs for HTTPS if the app needs them (copied from builder)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the compiled binary
COPY --from=builder /out/gotiny-oidc /usr/local/bin/gotiny-oidc

# Provide a default users.yaml and allow it to be overridden by a volume mount
COPY --from=builder /src/users.yaml /config/users.yaml
VOLUME ["/config"]

# Environment variables with sensible defaults. Users can override at runtime or via Dockerfile --env
ENV USERS="/config/users.yaml"
ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gotiny-oidc"]
