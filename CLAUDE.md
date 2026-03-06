# Claude Code Development Guide — OAuth Token Relay

## Project Overview

Generic OAuth 2.1 authorization server + multi-provider OAuth 2.0 token relay. Centralizes OAuth credential management: the server holds `client_secret`, clients hold tokens. The server facilitates OAuth flows but is never in the data path — API calls go directly from clients to providers.

**Companion project:** `../google-workspace` — Python CLI that uses this server in "server mode" (branch `feature/server-auth-provider`).

## Implementation Plan

The full 16-task implementation plan is at: `docs/plans/2026-02-15-oauth-token-relay.md`

Read the plan before starting any implementation work.

## Architecture

```
cmd/oauth-token-relay/main.go    — Entry point: config, store, server wiring
internal/
├── config/config.go             — YAML config with env var substitution
├── auth/
│   ├── jwt.go                   — JWT issuance + validation (HS256)
│   ├── oauth21.go               — OAuth 2.1 AS (Fosite: PKCE + device flow)
│   └── middleware.go            — Bearer token + admin role middleware
├── provider/
│   ├── provider.go              — Provider interface
│   ├── oauth2.go                — Generic OAuth 2.0 relay implementation
│   └── registry.go              — Load providers from config
├── store/
│   ├── store.go                 — Storage interface (Users, Tokens, Audit, etc.)
│   ├── sqlite.go                — SQLite implementation
│   └── backup.go                — S3 backup (SQLite only, not yet wired)
├── handler/
│   ├── health.go                — GET /health
│   ├── oauth.go                 — /oauth/* (PKCE, device flow, token exchange)
│   ├── relay.go                 — /auth/tokens/* (start, callback, complete, refresh, revoke)
│   └── admin.go                 — /admin/* (users, audit, providers, usage)
├── admin/
│   ├── handler.go               — Admin API handlers
│   └── ui/                      — templ + htmx admin dashboard
│       ├── embed.go
│       ├── static/
│       └── templates/
└── server/
    └── server.go                — HTTP server, middleware stack, graceful shutdown
```

## Key Patterns

### Storage Interface

All database access goes through the `Store` interface. Currently only `SQLiteStore` is implemented.

### Provider Registry

Providers are configured in YAML, not hardcoded. Multiple instances of the same provider type are supported (e.g., `google-corp` and `google-partner`). Provider IDs are user-defined strings.

### Token Security

- Server JWTs: HS256 signed with configurable key
- Refresh token hashes: SHA-256, never stored in plaintext
- Upstream tokens (Google, etc.): NEVER stored in database — processed in-memory only, returned to CLI

### Config Env Var Substitution

Config values like `${GOOGLE_CLIENT_SECRET}` are expanded via `os.ExpandEnv()` at load time.

## Running

```bash
# Development
go run ./cmd/oauth-token-relay -config config.yaml

# Tests
go test ./...

# Build
go build -o oauth-token-relay ./cmd/oauth-token-relay

# Docker
docker compose up
```

## Tech Stack

| Library | Purpose |
|---------|---------|
| `github.com/ory/fosite` | OAuth 2.1 AS (PKCE) |
| `golang.org/x/oauth2` | Upstream provider OAuth 2.0 client |
| `github.com/golang-jwt/jwt/v5` | JWT issuance and validation |
| `github.com/mattn/go-sqlite3` | SQLite driver |
| `github.com/a-h/templ` | Type-safe Go HTML templates |
| `github.com/aws/aws-sdk-go-v2` | S3 backup (not yet wired) |
| `gopkg.in/yaml.v3` | Config parsing |

## API Contract

See `docs/plans/2026-02-15-oauth-token-relay.md` for full API contract including:
- Health endpoint (no auth)
- OAuth 2.1 AS endpoints (PKCE + device flow)
- Token relay endpoints (requires server JWT)
- Admin endpoints (requires admin role)

## Database Schema

8 tables: `users`, `providers`, `server_refresh_tokens`, `auth_codes`, `device_codes`, `audit_log`, `usage_events`, `relay_sessions`. Full DDL in the plan document.

Code-driven migrations using `pragma_table_info()` + ALTER TABLE pattern (no migration framework).

## Development Workflow

- Use `superpowers:executing-plans` skill to implement the plan task-by-task
- Each task has TDD steps: write test → verify fail → implement → verify pass → commit
- Tasks have dependencies noted in the plan — follow the order
