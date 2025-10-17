FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git build-base ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=0 GOOS=linux
# Build the command located under cmd/tinygoidc
RUN go build -ldflags='-s -w' -o /out/tinygoidc ./cmd/tinygoidc
RUN apk add --no-cache upx
RUN upx --best --lzma /out/tinygoidc

# Final stage: minimal image
FROM scratch

# Add CA certs for HTTPS if the app needs them (copied from builder)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the compiled binary
COPY --from=builder /out/tinygoidc /usr/local/bin/tinygoidc

# Copy templates and static files
## templates/static are embedded into the binary via go:embed
# Provide a default users.yaml and allow it to be overridden by a volume mount
COPY --from=builder /src/users.yaml /config/users.yaml
VOLUME ["/config"]

# Environment variables with sensible defaults. Users can override at runtime or via Dockerfile --env
ENV USERS="/config/users.yaml"
ENV PORT=9999
ENV GIN_MODE=release

EXPOSE 9999

ENTRYPOINT ["/usr/local/bin/tinygoidc"]
