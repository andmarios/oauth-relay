# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /oauth-token-relay ./cmd/oauth-token-relay

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 1000 appuser

COPY --from=builder /oauth-token-relay /usr/local/bin/oauth-token-relay

RUN mkdir -p /data && chown appuser:appuser /data

USER appuser
WORKDIR /data

EXPOSE 8085

ENTRYPOINT ["oauth-token-relay"]
CMD ["-config", "/etc/oauth-token-relay/config.yaml"]
