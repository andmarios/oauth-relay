# OAuth Token Relay

Generic OAuth 2.1 authorization server + multi-provider OAuth 2.0 token relay.

Centralizes OAuth credential management: the server holds `client_secret`, clients hold tokens. The server facilitates OAuth flows but is never in the data path — API calls go directly from clients to providers.

## Quick Start

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your provider credentials
go run ./cmd/oauth-token-relay -config config.yaml
```

## Development

```bash
go test ./...
go build -o oauth-token-relay ./cmd/oauth-token-relay
```
