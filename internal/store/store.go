package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

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
// Upstream tokens are NEVER stored here — they live in-memory only (see RelayHandler.tokenCache).
type RelaySession struct {
	SessionID   string
	UserID      string
	ProviderID  string
	State       string // CSRF token for OAuth callback
	Scopes      string
	Status      string // pending, completed, expired
	CreatedAt   time.Time
	CompletedAt *time.Time
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
	ListAuditEntries(ctx context.Context, f *AuditFilter) ([]*AuditEntry, int, error)

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
