# OAuth Token Relay Server — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a generic OAuth 2.1 authorization server + multi-provider OAuth 2.0 token relay that centralizes OAuth credential management for CLI tools.

**Architecture:** Go HTTP server using Ory Fosite for OAuth 2.1 AS (PKCE + device flow). Provider relay facilitates upstream OAuth flows (Google, Microsoft, etc.) using server-held client_secret. CLI users authenticate to the server via PKCE/device flow, then request upstream tokens via the relay API. The server never stores upstream tokens — they pass through in-memory and are returned to the CLI. Storage is interface-driven with SQLite and PostgreSQL backends. Admin UI uses templ + htmx.

**Tech Stack:** Go 1.23+, Ory Fosite, golang-jwt/jwt/v5, go-sqlite3, pgx/v5, a-h/templ, htmx, aws-sdk-go-v2

---

## Repository Structure

```
oauth-token-relay/
├── cmd/oauth-token-relay/main.go
├── internal/
│   ├── config/config.go
│   ├── config/config_test.go
│   ├── auth/
│   │   ├── jwt.go
│   │   ├── jwt_test.go
│   │   ├── oauth21.go
│   │   ├── oauth21_test.go
│   │   ├── middleware.go
│   │   └── middleware_test.go
│   ├── provider/
│   │   ├── provider.go
│   │   ├── oauth2.go
│   │   ├── oauth2_test.go
│   │   ├── registry.go
│   │   └── registry_test.go
│   ├── store/
│   │   ├── store.go
│   │   ├── sqlite.go
│   │   ├── sqlite_test.go
│   │   ├── postgres.go
│   │   ├── postgres_test.go
│   │   ├── backup.go
│   │   └── backup_test.go
│   ├── handler/
│   │   ├── health.go
│   │   ├── health_test.go
│   │   ├── oauth.go
│   │   ├── oauth_test.go
│   │   ├── relay.go
│   │   ├── relay_test.go
│   │   └── admin.go
│   ├── admin/
│   │   ├── handler.go
│   │   ├── handler_test.go
│   │   └── ui/
│   │       ├── embed.go
│   │       ├── static/
│   │       │   ├── htmx.min.js
│   │       │   └── styles.css
│   │       └── templates/
│   │           ├── layout.templ
│   │           ├── dashboard.templ
│   │           ├── users.templ
│   │           ├── user_detail.templ
│   │           ├── audit.templ
│   │           └── providers.templ
│   └── server/
│       ├── server.go
│       └── server_test.go
├── Dockerfile
├── docker-compose.yml
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── pvc.yaml
│   └── kustomization.yaml
├── config.example.yaml
├── go.mod
├── go.sum
└── README.md
```

---

## Database Schema

All tables are created via code-driven migrations (pragma_table_info + ALTER TABLE pattern).

```sql
-- Users authenticated via the server's OAuth 2.1 AS
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    provider_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Configured OAuth providers (e.g., google-corp, google-partner)
CREATE TABLE providers (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    config TEXT NOT NULL  -- JSON: authorize_url, token_url, revoke_url, scopes_mapping, extra_params
);

-- Server refresh tokens (for the server's own OAuth 2.1 AS)
CREATE TABLE server_refresh_tokens (
    token_hash TEXT PRIMARY KEY,  -- SHA-256 of token, NEVER plaintext
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Authorization codes (PKCE)
CREATE TABLE auth_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Device flow codes
CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    user_id TEXT,  -- NULL until user approves
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'expired')),
    scopes TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    provider_id TEXT,
    action TEXT NOT NULL,
    details TEXT,  -- JSON
    ip_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Usage events for metrics
CREATE TABLE usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    provider_id TEXT,
    action TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Pending relay sessions (in-memory with DB fallback)
CREATE TABLE relay_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    state TEXT NOT NULL,  -- CSRF token for OAuth callback
    scopes TEXT NOT NULL,
    access_token TEXT,    -- Encrypted, temporary
    refresh_token TEXT,   -- Encrypted, temporary
    expires_in INTEGER,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'expired')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
```

---

## API Contract Reference

### Health (no auth)
```
GET /health → { "status": "ok", "providers": ["google-corp", ...] }
```

### OAuth 2.1 AS (CLI → server auth)
```
GET  /oauth/authorize        — PKCE authorization
POST /oauth/token            — code→tokens, refresh, device_code→tokens
POST /oauth/device           — device flow initiation
GET  /oauth/device/verify    — user approval page
POST /oauth/revoke           — token revocation
```

### Token Relay (requires Bearer <server_jwt>)
```
POST /auth/tokens/start      — { scopes: [...] } → { auth_url, session_id }
GET  /auth/tokens/callback   — browser redirect from provider (not called by CLI)
POST /auth/tokens/complete   — { session_id } → { access_token, refresh_token, expires_in }
POST /auth/tokens/refresh    — { refresh_token } → { access_token, expires_in }
POST /auth/tokens/revoke     — { token } → { success: true }
```

### Admin (requires Bearer <server_jwt> + admin role)
```
GET    /admin/users
GET    /admin/users/{id}
DELETE /admin/users/{id}
POST   /admin/users/{id}/assign-provider  — { provider_id }
GET    /admin/usage
GET    /admin/audit
GET    /admin/providers
```

---

## Task 1: Go Module + Dependencies + Project Scaffold

**Files:**
- Create: `go.mod`
- Create: `go.sum` (auto-generated)
- Create: `cmd/oauth-token-relay/main.go` (stub)
- Create: `config.example.yaml`
- Create: `README.md`
- Create: `.gitignore`

**Step 1: Initialize Go module**

```bash
cd /home/piper/development/mcp/oauth-token-relay
go mod init github.com/piper/oauth-token-relay
```

**Step 2: Add dependencies**

```bash
go get github.com/ory/fosite@latest
go get github.com/ory/fosite/handler/oauth2@latest
go get github.com/ory/fosite/handler/pkce@latest
go get github.com/golang-jwt/jwt/v5@latest
go get github.com/mattn/go-sqlite3@latest
go get github.com/jackc/pgx/v5@latest
go get github.com/jackc/pgx/v5/stdlib@latest
go get github.com/a-h/templ@latest
go get github.com/aws/aws-sdk-go-v2@latest
go get github.com/aws/aws-sdk-go-v2/config@latest
go get github.com/aws/aws-sdk-go-v2/service/s3@latest
go get golang.org/x/oauth2@latest
go get gopkg.in/yaml.v3@latest
go get github.com/google/uuid@latest
```

**Step 3: Create stub main.go**

```go
// cmd/oauth-token-relay/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "oauth-token-relay starting...")
	// TODO: Load config, init store, start server
	os.Exit(0)
}
```

**Step 4: Create config.example.yaml**

```yaml
# oauth-token-relay configuration
server:
  address: ":8080"
  read_timeout: 30s
  write_timeout: 30s
  shutdown_timeout: 15s

storage:
  driver: "sqlite"  # "sqlite" or "postgres"
  sqlite:
    path: "./data/relay.db"
  postgres:
    dsn: "postgres://user:pass@localhost:5432/relay?sslmode=disable"

backup:
  enabled: false
  bucket: ""
  prefix: "oauth-token-relay/"
  interval: 1h
  region: "us-east-1"

jwt:
  signing_key: "${JWT_SIGNING_KEY}"  # REQUIRED: 256-bit key, base64 encoded
  issuer: "oauth-token-relay"
  access_token_ttl: 1h
  refresh_token_ttl: 720h  # 30 days

providers:
  google-corp:
    display_name: "Google (example.com)"
    client_id: "${GOOGLE_CORP_CLIENT_ID}"
    client_secret: "${GOOGLE_CORP_CLIENT_SECRET}"
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: "https://oauth2.googleapis.com/token"
    revoke_url: "https://oauth2.googleapis.com/revoke"
    scopes_mapping:
      docs: "https://www.googleapis.com/auth/documents"
      sheets: "https://www.googleapis.com/auth/spreadsheets"
      slides: "https://www.googleapis.com/auth/presentations"
      drive: "https://www.googleapis.com/auth/drive"
      gmail: "https://www.googleapis.com/auth/gmail.modify"
      calendar: "https://www.googleapis.com/auth/calendar"
      contacts: "https://www.googleapis.com/auth/contacts"
      directory: "https://www.googleapis.com/auth/directory.readonly"
    extra_params:
      access_type: "offline"
      prompt: "consent"

admin:
  # First user with this email gets admin role automatically
  bootstrap_admins:
    - "admin@example.com"
```

**Step 5: Create .gitignore**

```
# Binaries
/oauth-token-relay
/cmd/oauth-token-relay/oauth-token-relay

# Data
/data/
*.db
*.db-journal
*.db-wal

# Config with secrets
config.yaml
!config.example.yaml

# Go
vendor/

# IDE
.idea/
.vscode/
*.swp
```

**Step 6: Create README.md**

```markdown
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
```

**Step 7: Verify build**

```bash
go build ./cmd/oauth-token-relay
```

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: scaffold Go project with dependencies and config"
```

---

## Task 2: Configuration Loading

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Step 1: Write the tests**

```go
// internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	yaml := `
server:
  address: ":9090"
  read_timeout: 10s
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "dGVzdC1rZXktMjU2LWJpdHMtbG9uZy1lbm91Z2g="
  issuer: "test"
  access_token_ttl: 30m
  refresh_token_ttl: 24h
providers:
  test-provider:
    display_name: "Test Provider"
    client_id: "test-id"
    client_secret: "test-secret"
    authorize_url: "https://example.com/auth"
    token_url: "https://example.com/token"
    scopes_mapping:
      docs: "https://example.com/scope/docs"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Server.Address != ":9090" {
		t.Errorf("address = %q, want :9090", cfg.Server.Address)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("driver = %q, want sqlite", cfg.Storage.Driver)
	}
	if cfg.JWT.AccessTokenTTL != 30*time.Minute {
		t.Errorf("access_token_ttl = %v, want 30m", cfg.JWT.AccessTokenTTL)
	}
	p, ok := cfg.Providers["test-provider"]
	if !ok {
		t.Fatal("provider test-provider not found")
	}
	if p.DisplayName != "Test Provider" {
		t.Errorf("display_name = %q, want Test Provider", p.DisplayName)
	}
	if p.ScopesMapping["docs"] != "https://example.com/scope/docs" {
		t.Errorf("scope docs = %q", p.ScopesMapping["docs"])
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	t.Setenv("TEST_SECRET", "expanded-secret")
	yaml := `
server:
  address: ":8080"
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "${TEST_SECRET}"
  issuer: "test"
providers: {}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.JWT.SigningKey != "expanded-secret" {
		t.Errorf("signing_key = %q, want expanded-secret", cfg.JWT.SigningKey)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	yaml := `
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "key"
  issuer: "test"
providers: {}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Server.Address != ":8080" {
		t.Errorf("default address = %q, want :8080", cfg.Server.Address)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("default read_timeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateConfig(t *testing.T) {
	// Missing signing key
	cfg := &Config{
		Storage: StorageConfig{Driver: "sqlite", SQLite: SQLiteConfig{Path: "./test.db"}},
		JWT:     JWTConfig{Issuer: "test"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing signing_key")
	}

	// Invalid storage driver
	cfg.JWT.SigningKey = "key"
	cfg.Storage.Driver = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid driver")
	}
}
```

**Step 2: Run tests — expect FAIL**

```bash
cd /home/piper/development/mcp/oauth-token-relay
go test ./internal/config/ -v
```

**Step 3: Implement config.go**

```go
// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for the OAuth Token Relay server.
type Config struct {
	Server   ServerConfig            `yaml:"server"`
	Storage  StorageConfig           `yaml:"storage"`
	Backup   BackupConfig            `yaml:"backup"`
	JWT      JWTConfig               `yaml:"jwt"`
	Providers map[string]ProviderConfig `yaml:"providers"`
	Admin    AdminConfig             `yaml:"admin"`
}

type ServerConfig struct {
	Address         string        `yaml:"address"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type StorageConfig struct {
	Driver   string         `yaml:"driver"`
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type SQLiteConfig struct {
	Path string `yaml:"path"`
}

type PostgresConfig struct {
	DSN string `yaml:"dsn"`
}

type BackupConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Bucket   string        `yaml:"bucket"`
	Prefix   string        `yaml:"prefix"`
	Interval time.Duration `yaml:"interval"`
	Region   string        `yaml:"region"`
}

type JWTConfig struct {
	SigningKey      string        `yaml:"signing_key"`
	Issuer         string        `yaml:"issuer"`
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
}

type ProviderConfig struct {
	DisplayName   string            `yaml:"display_name"`
	ClientID      string            `yaml:"client_id"`
	ClientSecret  string            `yaml:"client_secret"`
	AuthorizeURL  string            `yaml:"authorize_url"`
	TokenURL      string            `yaml:"token_url"`
	RevokeURL     string            `yaml:"revoke_url"`
	ScopesMapping map[string]string `yaml:"scopes_mapping"`
	ExtraParams   map[string]string `yaml:"extra_params"`
}

type AdminConfig struct {
	BootstrapAdmins []string `yaml:"bootstrap_admins"`
}

// Load reads a YAML config file, expands environment variables, and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Expand env vars (${VAR} syntax)
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Address == "" {
		c.Server.Address = ":8080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 30 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 30 * time.Second
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.JWT.AccessTokenTTL == 0 {
		c.JWT.AccessTokenTTL = 1 * time.Hour
	}
	if c.JWT.RefreshTokenTTL == 0 {
		c.JWT.RefreshTokenTTL = 720 * time.Hour
	}
	if c.Backup.Interval == 0 {
		c.Backup.Interval = 1 * time.Hour
	}
	if c.Backup.Prefix == "" {
		c.Backup.Prefix = "oauth-token-relay/"
	}
}

// Validate checks that required fields are present and values are sane.
func (c *Config) Validate() error {
	if c.JWT.SigningKey == "" {
		return fmt.Errorf("jwt.signing_key is required")
	}
	if c.Storage.Driver != "sqlite" && c.Storage.Driver != "postgres" {
		return fmt.Errorf("storage.driver must be 'sqlite' or 'postgres', got %q", c.Storage.Driver)
	}
	if c.Storage.Driver == "sqlite" && c.Storage.SQLite.Path == "" {
		return fmt.Errorf("storage.sqlite.path is required when driver is sqlite")
	}
	if c.Storage.Driver == "postgres" && c.Storage.Postgres.DSN == "" {
		return fmt.Errorf("storage.postgres.dsn is required when driver is postgres")
	}
	return nil
}
```

**Step 4: Run tests — expect PASS**

```bash
go test ./internal/config/ -v
```

**Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat: add config loading with env expansion and validation"
```

---

## Task 3: Storage Interface + SQLite Implementation

**Files:**
- Create: `internal/store/store.go` (interface)
- Create: `internal/store/sqlite.go`
- Create: `internal/store/sqlite_test.go`

**Step 1: Write store interface**

The `Store` interface defines ALL storage operations. Each method maps to a SQL operation. Keep it flat — no nested interfaces.

```go
// internal/store/store.go
package store

import (
	"context"
	"time"
)

// User represents an authenticated user of the relay server.
type User struct {
	ID         string
	Email      string
	Name       string
	Role       string // "user" or "admin"
	ProviderID string
	CreatedAt  time.Time
	LastLogin  *time.Time
}

// Provider represents a configured OAuth provider instance.
type Provider struct {
	ID          string
	DisplayName string
	Config      []byte // JSON blob
}

// RefreshToken represents a server-issued refresh token.
type RefreshToken struct {
	TokenHash string // SHA-256
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// AuthCode represents a PKCE authorization code.
type AuthCode struct {
	CodeHash            string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	Scopes              string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// DeviceCode represents a device flow authorization request.
type DeviceCode struct {
	DeviceCodeHash string
	UserCode       string
	UserID         string // empty until approved
	Status         string // pending, approved, denied, expired
	Scopes         string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID         int64
	UserID     string
	ProviderID string
	Action     string
	Details    string // JSON
	IPAddress  string
	CreatedAt  time.Time
}

// UsageEvent represents a usage tracking event.
type UsageEvent struct {
	ID         int64
	UserID     string
	ProviderID string
	Action     string
	CreatedAt  time.Time
}

// RelaySession tracks a pending token relay flow.
type RelaySession struct {
	SessionID    string
	UserID       string
	ProviderID   string
	State        string // CSRF token for OAuth callback
	Scopes       string
	AccessToken  string // encrypted, temporary
	RefreshToken string // encrypted, temporary
	ExpiresIn    int
	Status       string // pending, completed, expired
	CreatedAt    time.Time
	CompletedAt  *time.Time
}

// AuditFilter specifies criteria for querying audit logs.
type AuditFilter struct {
	UserID     string
	ProviderID string
	Action     string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// Store defines all storage operations for the relay server.
type Store interface {
	// Lifecycle
	Close() error
	Migrate(ctx context.Context) error

	// Users
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, limit, offset int) ([]*User, int, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	UpdateLastLogin(ctx context.Context, id string) error

	// Providers
	UpsertProvider(ctx context.Context, p *Provider) error
	GetProvider(ctx context.Context, id string) (*Provider, error)
	ListProviders(ctx context.Context) ([]*Provider, error)
	DeleteProvider(ctx context.Context, id string) error

	// Server refresh tokens
	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteUserRefreshTokens(ctx context.Context, userID string) error
	CleanExpiredRefreshTokens(ctx context.Context) (int64, error)

	// Auth codes (PKCE)
	CreateAuthCode(ctx context.Context, c *AuthCode) error
	GetAuthCode(ctx context.Context, codeHash string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, codeHash string) error
	CleanExpiredAuthCodes(ctx context.Context) (int64, error)

	// Device codes
	CreateDeviceCode(ctx context.Context, d *DeviceCode) error
	GetDeviceCode(ctx context.Context, deviceCodeHash string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, d *DeviceCode) error
	CleanExpiredDeviceCodes(ctx context.Context) (int64, error)

	// Audit log
	CreateAuditEntry(ctx context.Context, e *AuditEntry) error
	ListAuditEntries(ctx context.Context, f AuditFilter) ([]*AuditEntry, int, error)

	// Usage events
	CreateUsageEvent(ctx context.Context, e *UsageEvent) error
	GetUsageStats(ctx context.Context, since time.Time) (map[string]int64, error)

	// Relay sessions
	CreateRelaySession(ctx context.Context, s *RelaySession) error
	GetRelaySession(ctx context.Context, sessionID string) (*RelaySession, error)
	GetRelaySessionByState(ctx context.Context, state string) (*RelaySession, error)
	UpdateRelaySession(ctx context.Context, s *RelaySession) error
	CleanExpiredRelaySessions(ctx context.Context) (int64, error)
}
```

**Step 2: Write SQLite tests**

Test file should cover: Open/Close, Migrate, CRUD for each entity type.

See `internal/store/sqlite_test.go` — test each method with table-driven tests. Focus on:
- CreateUser + GetUser + GetUserByEmail
- UpsertProvider + GetProvider + ListProviders
- CRUD for RefreshToken, AuthCode, DeviceCode
- CreateAuditEntry + ListAuditEntries with filters
- RelaySession lifecycle: create → update → get → clean

Each test creates a fresh temp DB, runs Migrate, then exercises the method.

**Step 3: Implement SQLite store**

In `internal/store/sqlite.go`:
- Open with pragmas: `_journal_mode=WAL`, `_synchronous=NORMAL`, `_cache_size=10000`, `_busy_timeout=5000`
- `Migrate()` creates all tables using `CREATE TABLE IF NOT EXISTS`
- Each CRUD method uses prepared statements
- Use `database/sql` with `github.com/mattn/go-sqlite3` driver

**Step 4: Run tests — expect PASS**

```bash
CGO_ENABLED=1 go test ./internal/store/ -v -run TestSQLite
```

**Step 5: Commit**

```bash
git add internal/store/
git commit -m "feat: add Store interface and SQLite implementation"
```

---

## Task 4: PostgreSQL Implementation

**Files:**
- Create: `internal/store/postgres.go`
- Create: `internal/store/postgres_test.go`

Same interface, PostgreSQL dialect. Uses `pgx/v5/stdlib` for `database/sql` compatibility. Tests require a running PostgreSQL instance (skip with build tag or env check).

**Step 1-4:** Mirror SQLite pattern with PostgreSQL syntax (e.g., `$1` params, `SERIAL` → `BIGSERIAL`, `TEXT` → `TEXT`).

**Step 5: Commit**

```bash
git add internal/store/postgres.go internal/store/postgres_test.go
git commit -m "feat: add PostgreSQL Store implementation"
```

---

## Task 5: JWT Issuance and Validation

**Files:**
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/jwt_test.go`

**Key design:**
- HMAC-SHA256 signing (HS256) using the configured `jwt.signing_key`
- Access token: short-lived (1h default), contains `sub` (user ID), `email`, `role`, `provider_id`
- Refresh token: long-lived (30d default), contains `sub` only + `jti` for revocation
- Custom claims struct with standard JWT fields

**Tests:** Issue token, validate it, check claims, test expired tokens, test tampered tokens, test refresh flow.

**Step 5: Commit**

```bash
git add internal/auth/jwt.go internal/auth/jwt_test.go
git commit -m "feat: add JWT issuance and validation"
```

---

## Task 6: Auth Middleware

**Files:**
- Create: `internal/auth/middleware.go`
- Create: `internal/auth/middleware_test.go`

**Key design:**
- `RequireAuth` middleware: extracts Bearer token from Authorization header, validates JWT, injects claims into context
- `RequireAdmin` middleware: wraps RequireAuth, additionally checks `role == "admin"`
- Context helpers: `UserFromContext(ctx)`, `ClaimsFromContext(ctx)`

**Tests:** Valid token → 200, missing token → 401, expired token → 401, non-admin on admin route → 403.

**Step 5: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_test.go
git commit -m "feat: add auth middleware with role-based access"
```

---

## Task 7: Provider Interface + Registry

**Files:**
- Create: `internal/provider/provider.go`
- Create: `internal/provider/oauth2.go`
- Create: `internal/provider/oauth2_test.go`
- Create: `internal/provider/registry.go`
- Create: `internal/provider/registry_test.go`

**Key design:**

```go
// provider.go
type Provider interface {
    ID() string
    DisplayName() string
    AuthURL(state string, scopes []string) string
    Exchange(ctx context.Context, code string) (*TokenResult, error)
    Refresh(ctx context.Context, refreshToken string) (*TokenResult, error)
    Revoke(ctx context.Context, token string) error
}

type TokenResult struct {
    AccessToken  string
    RefreshToken string
    ExpiresIn    int
    Scopes       []string
}
```

- `oauth2.go`: Generic OAuth 2.0 provider using `golang.org/x/oauth2`. Handles authorize URL construction, code exchange, refresh, revoke. Uses `scopes_mapping` to translate short names → full URLs. Passes `extra_params`.
- `registry.go`: Loads providers from config. `Get(id) Provider`, `List() []Provider`, `ResolveForUser(user) Provider` (looks up user's `provider_id`).

**Tests:** Build provider from config, test AuthURL generation, mock token exchange.

**Step 5: Commit**

```bash
git add internal/provider/
git commit -m "feat: add provider interface, OAuth 2.0 relay, and registry"
```

---

## Task 8: HTTP Server + Security Middleware

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

**Key design:**
- Uses `net/http.ServeMux` (Go 1.22+ pattern routing)
- Security headers middleware: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy
- CORS middleware (configurable origins)
- Request logging middleware
- Route registration (wires all handlers)
- Graceful shutdown with context cancellation

**Tests:** Server starts and serves /health, security headers present, graceful shutdown works.

**Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: add HTTP server with security middleware"
```

---

## Task 9: Health + OAuth Handlers

**Files:**
- Create: `internal/handler/health.go`
- Create: `internal/handler/health_test.go`
- Create: `internal/handler/oauth.go`
- Create: `internal/handler/oauth_test.go`

**Health handler:**
```go
GET /health → { "status": "ok", "providers": ["google-corp", ...] }
```

**OAuth handlers** (integrate Fosite):
- `GET /oauth/authorize` — PKCE authorization endpoint. Renders consent page or redirects.
- `POST /oauth/token` — Handles `authorization_code` (PKCE), `refresh_token`, and `device_code` grant types.
- `POST /oauth/device` — Device flow initiation. Returns `device_code`, `user_code`, `verification_uri`.
- `GET /oauth/device/verify` — User-facing page to enter device code and approve.
- `POST /oauth/revoke` — Token revocation.

**Fosite integration notes:**
- Create Fosite `OAuth2Provider` with PKCE handler, refresh token handler, device code handler
- Implement Fosite storage interface backed by our `Store`
- Use `fosite.DefaultOpenIDConnectClient` or custom client

**Tests:** Health returns provider list. OAuth endpoints return correct status codes for valid/invalid requests.

**Step 5: Commit**

```bash
git add internal/handler/health.go internal/handler/health_test.go
git add internal/handler/oauth.go internal/handler/oauth_test.go
git commit -m "feat: add health and OAuth 2.1 handlers with Fosite"
```

---

## Task 10: Token Relay Handlers

**Files:**
- Create: `internal/handler/relay.go`
- Create: `internal/handler/relay_test.go`

This is the core novel feature — the token relay.

**Handlers:**

```
POST /auth/tokens/start
```
- Requires Bearer auth (server JWT)
- Body: `{ "scopes": ["docs", "sheets"] }`
- Resolves user → provider from JWT claims
- Creates relay session in DB
- Generates state token (CSRF)
- Uses provider to build auth URL with translated scopes
- Returns `{ "auth_url": "...", "session_id": "..." }`

```
GET /auth/tokens/callback
```
- Browser redirect from OAuth provider
- Extracts `code` and `state` from query
- Looks up relay session by state
- Uses provider to exchange code for tokens
- Stores tokens in relay session (encrypted, 5-min TTL)
- Renders success HTML page (tells user to return to CLI)

```
POST /auth/tokens/complete
```
- Requires Bearer auth
- Body: `{ "session_id": "abc" }`
- Looks up relay session
- If completed: returns tokens and deletes session
- If pending: returns 202 (CLI polls)
- If expired: returns 410

```
POST /auth/tokens/refresh
```
- Requires Bearer auth
- Body: `{ "refresh_token": "1//..." }`
- Resolves user → provider
- Uses provider to refresh upstream token
- Returns `{ "access_token": "ya29...", "expires_in": 3600 }`

```
POST /auth/tokens/revoke
```
- Requires Bearer auth
- Body: `{ "token": "1//..." }`
- Resolves user → provider
- Uses provider to revoke upstream token
- Returns `{ "success": true }`

**Tests:** Mock provider + mock store. Test each handler with valid/invalid requests, test relay session lifecycle.

**Step 5: Commit**

```bash
git add internal/handler/relay.go internal/handler/relay_test.go
git commit -m "feat: add token relay handlers (start/callback/complete/refresh/revoke)"
```

---

## Task 11: Admin API Handlers

**Files:**
- Create: `internal/handler/admin.go`
- Create: `internal/handler/admin_test.go`

All admin endpoints require Bearer auth + admin role (via RequireAdmin middleware).

**Handlers:**
```
GET    /admin/users              — ListUsers with pagination
GET    /admin/users/{id}         — GetUser with audit history
DELETE /admin/users/{id}         — DeleteUser + revoke tokens
POST   /admin/users/{id}/assign-provider — Update user's provider_id
GET    /admin/usage              — Aggregate usage stats
GET    /admin/audit              — ListAuditEntries with filters
GET    /admin/providers          — ListProviders with usage counts
```

**Tests:** CRUD operations with mocked store.

**Step 5: Commit**

```bash
git add internal/handler/admin.go internal/handler/admin_test.go
git commit -m "feat: add admin API handlers"
```

---

## Task 12: S3 Backup (SQLite)

**Files:**
- Create: `internal/store/backup.go`
- Create: `internal/store/backup_test.go`

**Key design:**
- Runs on configurable interval (default 1h)
- Uses SQLite backup API via `.backup` command or file copy with WAL checkpoint
- Uploads to S3 with instance lock (heartbeat-based, prevents concurrent backups)
- Prefix: `{bucket}/{prefix}/relay.db`
- Lock key: `{prefix}/lock.json` with instance ID + heartbeat timestamp

**Tests:** Mock S3 client, test backup lifecycle.

**Step 5: Commit**

```bash
git add internal/store/backup.go internal/store/backup_test.go
git commit -m "feat: add S3 backup for SQLite with distributed locking"
```

---

## Task 13: Admin UI (templ + htmx)

**Files:**
- Create: `internal/admin/handler.go`
- Create: `internal/admin/ui/embed.go`
- Create: `internal/admin/ui/static/styles.css`
- Create: `internal/admin/ui/static/htmx.min.js` (vendored)
- Create: `internal/admin/ui/templates/*.templ`

**Pages:**
- Dashboard: user count, auth events today, per-provider breakdown
- Users: searchable table with actions
- User Detail: audit history, per-provider usage, revoke sessions
- Audit Log: filterable by user, provider, action, date range
- Providers: configured providers with status

**Design:** Server-rendered HTML with htmx for dynamic updates. No SPA. Minimal CSS. Admin handler serves static assets via `go:embed` and renders templ templates.

**Step 1:** Install templ CLI and generate Go code from .templ files.

```bash
go install github.com/a-h/templ/cmd/templ@latest
templ generate ./internal/admin/ui/templates/
```

**Step 5: Commit**

```bash
git add internal/admin/
git commit -m "feat: add admin UI with templ + htmx"
```

---

## Task 14: Main Entry Point + Wire Everything

**Files:**
- Modify: `cmd/oauth-token-relay/main.go`

**Key design:**
- Parse CLI flags: `-config path`
- Load and validate config
- Initialize store (SQLite or PostgreSQL based on config)
- Run migrations
- Initialize provider registry from config
- Initialize JWT service
- Build HTTP server with all handlers wired
- Start S3 backup goroutine if enabled
- Handle SIGINT/SIGTERM for graceful shutdown
- Bootstrap admin users from config

**Step 5: Commit**

```bash
git add cmd/oauth-token-relay/main.go
git commit -m "feat: wire main entry point with config, store, and server"
```

---

## Task 15: Dockerfile + docker-compose + K8s

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `k8s/deployment.yaml`
- Create: `k8s/service.yaml`
- Create: `k8s/ingress.yaml`
- Create: `k8s/pvc.yaml`
- Create: `k8s/kustomization.yaml`

**Dockerfile:** Multi-stage build. Builder: `golang:1.23-alpine` with `CGO_ENABLED=1` (for go-sqlite3). Runtime: `alpine:3.20` with `ca-certificates`.

**docker-compose.yml:** Single service with volume mount for data, env vars for secrets, port 8080.

**K8s:** Single-replica Deployment (SQLite), Service (ClusterIP), Ingress (TLS via cert-manager), PVC for SQLite data, Kustomization for ArgoCD.

**Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml k8s/
git commit -m "feat: add Docker and Kubernetes deployment manifests"
```

---

## Task 16: End-to-End Integration Test

**Files:**
- Create: `integration_test.go` (build tag: `//go:build integration`)

**Test scenario:**
1. Start server with SQLite + test config
2. Create test user via direct store call
3. Exercise health endpoint
4. Exercise OAuth PKCE flow (programmatic)
5. Exercise token relay flow with mock provider
6. Exercise admin endpoints
7. Verify audit log entries

```bash
go test -tags integration -v ./...
```

**Step 5: Commit**

```bash
git add integration_test.go
git commit -m "test: add end-to-end integration test"
```

---

## Execution Order Summary

| Task | Component | Depends On | Parallelizable |
|------|-----------|-----------|----------------|
| 1 | Scaffold + deps | — | — |
| 2 | Config loading | 1 | — |
| 3 | Store interface + SQLite | 1 | Yes with 2 |
| 4 | PostgreSQL store | 3 | — |
| 5 | JWT | 1 | Yes with 2,3 |
| 6 | Auth middleware | 5 | — |
| 7 | Provider + registry | 2 | Yes with 3,5 |
| 8 | HTTP server | 6 | — |
| 9 | Health + OAuth handlers | 3, 6, 8 | — |
| 10 | Token relay handlers | 7, 8, 9 | — |
| 11 | Admin handlers | 6, 8 | Yes with 10 |
| 12 | S3 backup | 3 | Yes with 5-11 |
| 13 | Admin UI | 11 | — |
| 14 | Main entry point | ALL | — |
| 15 | Docker + K8s | 14 | — |
| 16 | Integration test | 14 | — |
