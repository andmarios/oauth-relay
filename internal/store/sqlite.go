package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteStore opens a SQLite database at the given path with WAL mode.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_busy_timeout=5000", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &SQLiteStore{db: db, path: path}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
			provider_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS providers (
			id TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			config TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS server_refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS auth_codes (
			code_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL DEFAULT 'S256',
			redirect_uri TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS device_codes (
			device_code_hash TEXT PRIMARY KEY,
			user_code TEXT UNIQUE NOT NULL,
			user_id TEXT,
			status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'expired')),
			scopes TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT,
			provider_id TEXT,
			action TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS usage_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL,
			provider_id TEXT,
			action TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS relay_sessions (
			session_id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider_id TEXT NOT NULL,
			state TEXT NOT NULL,
			scopes TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'expired')),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP
		)`,
	}
	for _, ddl := range tables {
		if _, err := s.db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Enable foreign keys
	_, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	return err
}

// --- Users ---

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, provider_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.Role, u.ProviderID, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, role, provider_id, created_at, last_login FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.ProviderID, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user %q: %w", id, ErrNotFound)
	}
	return u, err
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, role, provider_id, created_at, last_login FROM users WHERE email = ?`, email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.ProviderID, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user email %q: %w", email, ErrNotFound)
	}
	return u, err
}

func (s *SQLiteStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, name, role, provider_id, created_at, last_login FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.ProviderID, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, name = ?, role = ?, provider_id = ? WHERE id = ?`,
		u.Email, u.Name, u.Role, u.ProviderID, u.ID,
	)
	return err
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login = ? WHERE id = ?`, time.Now().UTC(), id,
	)
	return err
}

// --- Providers ---

func (s *SQLiteStore) UpsertProvider(ctx context.Context, p *Provider) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO providers (id, display_name, config) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, config = excluded.config`,
		p.ID, p.DisplayName, p.Config,
	)
	return err
}

func (s *SQLiteStore) GetProvider(ctx context.Context, id string) (*Provider, error) {
	p := &Provider{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, display_name, config FROM providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.DisplayName, &p.Config)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("provider %q: %w", id, ErrNotFound)
	}
	return p, err
}

func (s *SQLiteStore) ListProviders(ctx context.Context) ([]*Provider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, display_name, config FROM providers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*Provider
	for rows.Next() {
		p := &Provider{}
		if err := rows.Scan(&p.ID, &p.DisplayName, &p.Config); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

func (s *SQLiteStore) DeleteProvider(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE id = ?`, id)
	return err
}

// --- Server Refresh Tokens ---

func (s *SQLiteStore) CreateRefreshToken(ctx context.Context, t *RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO server_refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		t.TokenHash, t.UserID, t.ExpiresAt.UTC(), time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	t := &RefreshToken{}
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at FROM server_refresh_tokens WHERE token_hash = ?`, tokenHash,
	).Scan(&t.TokenHash, &t.UserID, &t.ExpiresAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token: %w", ErrNotFound)
	}
	return t, err
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM server_refresh_tokens WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("refresh token: %w", ErrNotFound)
	}
	return nil
}

func (s *SQLiteStore) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM server_refresh_tokens WHERE user_id = ?`, userID)
	return err
}

func (s *SQLiteStore) CleanExpiredRefreshTokens(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM server_refresh_tokens WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Auth Codes ---

func (s *SQLiteStore) CreateAuthCode(ctx context.Context, c *AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_codes (code_hash, user_id, code_challenge, code_challenge_method, redirect_uri, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CodeHash, c.UserID, c.CodeChallenge, c.CodeChallengeMethod, c.RedirectURI, c.Scopes, c.ExpiresAt.UTC(), time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetAuthCode(ctx context.Context, codeHash string) (*AuthCode, error) {
	c := &AuthCode{}
	err := s.db.QueryRowContext(ctx,
		`SELECT code_hash, user_id, code_challenge, code_challenge_method, redirect_uri, scopes, expires_at, created_at FROM auth_codes WHERE code_hash = ?`, codeHash,
	).Scan(&c.CodeHash, &c.UserID, &c.CodeChallenge, &c.CodeChallengeMethod, &c.RedirectURI, &c.Scopes, &c.ExpiresAt, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("auth code: %w", ErrNotFound)
	}
	return c, err
}

func (s *SQLiteStore) DeleteAuthCode(ctx context.Context, codeHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE code_hash = ?`, codeHash)
	return err
}

func (s *SQLiteStore) CleanExpiredAuthCodes(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Device Codes ---

func (s *SQLiteStore) CreateDeviceCode(ctx context.Context, d *DeviceCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_codes (device_code_hash, user_code, user_id, status, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceCodeHash, d.UserCode, d.UserID, d.Status, d.Scopes, d.ExpiresAt.UTC(), time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetDeviceCode(ctx context.Context, deviceCodeHash string) (*DeviceCode, error) {
	d := &DeviceCode{}
	err := s.db.QueryRowContext(ctx,
		`SELECT device_code_hash, user_code, COALESCE(user_id, ''), status, scopes, expires_at, created_at FROM device_codes WHERE device_code_hash = ?`, deviceCodeHash,
	).Scan(&d.DeviceCodeHash, &d.UserCode, &d.UserID, &d.Status, &d.Scopes, &d.ExpiresAt, &d.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device code: %w", ErrNotFound)
	}
	return d, err
}

func (s *SQLiteStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	d := &DeviceCode{}
	err := s.db.QueryRowContext(ctx,
		`SELECT device_code_hash, user_code, COALESCE(user_id, ''), status, scopes, expires_at, created_at FROM device_codes WHERE user_code = ?`, userCode,
	).Scan(&d.DeviceCodeHash, &d.UserCode, &d.UserID, &d.Status, &d.Scopes, &d.ExpiresAt, &d.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device code user_code %q: %w", userCode, ErrNotFound)
	}
	return d, err
}

func (s *SQLiteStore) UpdateDeviceCode(ctx context.Context, d *DeviceCode) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_codes SET user_id = ?, status = ? WHERE device_code_hash = ?`,
		d.UserID, d.Status, d.DeviceCodeHash,
	)
	return err
}

func (s *SQLiteStore) CleanExpiredDeviceCodes(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_codes WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Audit Log ---

func (s *SQLiteStore) CreateAuditEntry(ctx context.Context, e *AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, provider_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.UserID, e.ProviderID, e.Action, e.Details, e.IPAddress, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) ListAuditEntries(ctx context.Context, f AuditFilter) ([]*AuditEntry, int, error) {
	where := "WHERE 1=1"
	args := []any{}

	if f.UserID != "" {
		where += " AND user_id = ?"
		args = append(args, f.UserID)
	}
	if f.ProviderID != "" {
		where += " AND provider_id = ?"
		args = append(args, f.ProviderID)
	}
	if f.Action != "" {
		where += " AND action = ?"
		args = append(args, f.Action)
	}
	if f.Since != nil {
		where += " AND created_at >= ?"
		args = append(args, f.Since.UTC())
	}
	if f.Until != nil {
		where += " AND created_at <= ?"
		args = append(args, f.Until.UTC())
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf("SELECT id, COALESCE(user_id, ''), COALESCE(provider_id, ''), action, COALESCE(details, ''), COALESCE(ip_address, ''), created_at FROM audit_log %s ORDER BY id DESC LIMIT ? OFFSET ?", where)
	args = append(args, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		if err := rows.Scan(&e.ID, &e.UserID, &e.ProviderID, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// --- Usage Events ---

func (s *SQLiteStore) CreateUsageEvent(ctx context.Context, e *UsageEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO usage_events (user_id, provider_id, action, created_at) VALUES (?, ?, ?, ?)`,
		e.UserID, e.ProviderID, e.Action, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetUsageStats(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT action, COUNT(*) FROM usage_events WHERE created_at >= ? GROUP BY action`, since.UTC(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int64)
	for rows.Next() {
		var action string
		var count int64
		if err := rows.Scan(&action, &count); err != nil {
			return nil, err
		}
		stats[action] = count
	}
	return stats, rows.Err()
}

// --- Relay Sessions ---

func (s *SQLiteStore) CreateRelaySession(ctx context.Context, sess *RelaySession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO relay_sessions (session_id, user_id, provider_id, state, scopes, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sess.SessionID, sess.UserID, sess.ProviderID, sess.State, sess.Scopes, sess.Status, time.Now().UTC(),
	)
	return err
}

func (s *SQLiteStore) GetRelaySession(ctx context.Context, sessionID string) (*RelaySession, error) {
	sess := &RelaySession{}
	err := s.db.QueryRowContext(ctx,
		`SELECT session_id, user_id, provider_id, state, scopes, status, created_at, completed_at FROM relay_sessions WHERE session_id = ?`, sessionID,
	).Scan(&sess.SessionID, &sess.UserID, &sess.ProviderID, &sess.State, &sess.Scopes, &sess.Status, &sess.CreatedAt, &sess.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("relay session %q: %w", sessionID, ErrNotFound)
	}
	return sess, err
}

func (s *SQLiteStore) GetRelaySessionByState(ctx context.Context, state string) (*RelaySession, error) {
	sess := &RelaySession{}
	err := s.db.QueryRowContext(ctx,
		`SELECT session_id, user_id, provider_id, state, scopes, status, created_at, completed_at FROM relay_sessions WHERE state = ?`, state,
	).Scan(&sess.SessionID, &sess.UserID, &sess.ProviderID, &sess.State, &sess.Scopes, &sess.Status, &sess.CreatedAt, &sess.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("relay session by state: %w", ErrNotFound)
	}
	return sess, err
}

func (s *SQLiteStore) UpdateRelaySession(ctx context.Context, sess *RelaySession) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE relay_sessions SET status = ?, completed_at = ? WHERE session_id = ?`,
		sess.Status, sess.CompletedAt, sess.SessionID,
	)
	return err
}

func (s *SQLiteStore) CleanExpiredRelaySessions(ctx context.Context) (int64, error) {
	// Clean pending sessions older than 1 hour and completed sessions older than 5 minutes
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM relay_sessions WHERE
		 (status = 'pending' AND created_at < datetime('now', '-1 hour'))
		 OR (status = 'completed' AND completed_at < datetime('now', '-5 minutes'))`,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
