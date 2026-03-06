package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestSQLite(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteUserCRUD(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	u := &User{
		ID:    "u1",
		Email: "alice@example.com",
		Name:  "Alice",
		Role:  "user",
	}

	// Create
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Get by ID
	got, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", got.Email)
	}
	if got.Role != "user" {
		t.Errorf("role = %q, want user", got.Role)
	}

	// Get by email
	got, err = s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("id = %q, want u1", got.ID)
	}

	// Update
	u.Name = "Alice Updated"
	u.Role = "admin"
	if err = s.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, err = s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser after update: %v", err)
	}
	if got.Name != "Alice Updated" {
		t.Errorf("name = %q, want Alice Updated", got.Name)
	}
	if got.Role != "admin" {
		t.Errorf("role = %q, want admin", got.Role)
	}

	// UpdateLastLogin
	if err = s.UpdateLastLogin(ctx, "u1"); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}
	got, err = s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetUser after login: %v", err)
	}
	if got.LastLogin == nil {
		t.Error("LastLogin should be set")
	}

	// List
	users, total, err := s.ListUsers(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 {
		t.Errorf("len = %d, want 1", len(users))
	}

	// Delete
	if err = s.DeleteUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err = s.GetUser(ctx, "u1")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteProviderCRUD(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	p := &Provider{
		ID:          "google-corp",
		DisplayName: "Google Corp",
		Config:      []byte(`{"authorize_url":"https://accounts.google.com"}`),
	}

	// Upsert (create)
	if err := s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("UpsertProvider: %v", err)
	}

	// Get
	got, err := s.GetProvider(ctx, "google-corp")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.DisplayName != "Google Corp" {
		t.Errorf("display_name = %q", got.DisplayName)
	}

	// Upsert (update)
	p.DisplayName = "Google Updated"
	if err = s.UpsertProvider(ctx, p); err != nil {
		t.Fatalf("UpsertProvider update: %v", err)
	}
	got, err = s.GetProvider(ctx, "google-corp")
	if err != nil {
		t.Fatalf("GetProvider after update: %v", err)
	}
	if got.DisplayName != "Google Updated" {
		t.Errorf("display_name = %q, want Google Updated", got.DisplayName)
	}

	// List
	providers, err := s.ListProviders(ctx)
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(providers) != 1 {
		t.Errorf("len = %d, want 1", len(providers))
	}

	// Delete
	if err = s.DeleteProvider(ctx, "google-corp"); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	_, err = s.GetProvider(ctx, "google-corp")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteRefreshTokenCRUD(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	// Need a user first
	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	rt := &RefreshToken{
		TokenHash: "hash123",
		UserID:    "u1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got, err := s.GetRefreshToken(ctx, "hash123")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if got.UserID != "u1" {
		t.Errorf("user_id = %q", got.UserID)
	}

	if err = s.DeleteRefreshToken(ctx, "hash123"); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	_, err = s.GetRefreshToken(ctx, "hash123")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteRefreshTokenCleanExpired(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	// Create one expired, one valid
	s.CreateRefreshToken(ctx, &RefreshToken{
		TokenHash: "expired",
		UserID:    "u1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	s.CreateRefreshToken(ctx, &RefreshToken{
		TokenHash: "valid",
		UserID:    "u1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	cleaned, err := s.CleanExpiredRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredRefreshTokens: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1", cleaned)
	}
}

func TestSQLiteAuthCodeCRUD(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	ac := &AuthCode{
		CodeHash:            "code-hash",
		UserID:              "u1",
		CodeChallenge:       "challenge123",
		CodeChallengeMethod: "S256",
		RedirectURI:         "http://localhost:8080/callback",
		Scopes:              "openid email",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := s.CreateAuthCode(ctx, ac); err != nil {
		t.Fatalf("CreateAuthCode: %v", err)
	}

	got, err := s.GetAuthCode(ctx, "code-hash")
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if got.CodeChallenge != "challenge123" {
		t.Errorf("code_challenge = %q", got.CodeChallenge)
	}

	if err := s.DeleteAuthCode(ctx, "code-hash"); err != nil {
		t.Fatalf("DeleteAuthCode: %v", err)
	}
}

func TestSQLiteDeviceCodeCRUD(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	dc := &DeviceCode{
		DeviceCodeHash: "dev-hash",
		UserCode:       "ABCD-1234",
		Status:         "pending",
		Scopes:         "openid",
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	if err := s.CreateDeviceCode(ctx, dc); err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}

	// Get by hash
	got, err := s.GetDeviceCode(ctx, "dev-hash")
	if err != nil {
		t.Fatalf("GetDeviceCode: %v", err)
	}
	if got.UserCode != "ABCD-1234" {
		t.Errorf("user_code = %q", got.UserCode)
	}

	// Get by user code
	got, err = s.GetDeviceCodeByUserCode(ctx, "ABCD-1234")
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode: %v", err)
	}
	if got.DeviceCodeHash != "dev-hash" {
		t.Errorf("device_code_hash = %q", got.DeviceCodeHash)
	}

	// Update (approve)
	dc.Status = "approved"
	dc.UserID = "u1"
	if err = s.UpdateDeviceCode(ctx, dc); err != nil {
		t.Fatalf("UpdateDeviceCode: %v", err)
	}
	got, err = s.GetDeviceCode(ctx, "dev-hash")
	if err != nil {
		t.Fatalf("GetDeviceCode after update: %v", err)
	}
	if got.Status != "approved" {
		t.Errorf("status = %q, want approved", got.Status)
	}
}

func TestSQLiteAuditLog(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		s.CreateAuditEntry(ctx, &AuditEntry{
			UserID:     "u1",
			ProviderID: "google",
			Action:     "token_exchange",
			Details:    `{"scopes":["docs"]}`,
			IPAddress:  "127.0.0.1",
		})
	}

	entries, total, err := s.ListAuditEntries(ctx, &AuditFilter{
		UserID: "u1",
		Limit:  3,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(entries) != 3 {
		t.Errorf("len = %d, want 3", len(entries))
	}
}

func TestSQLiteUsageStats(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	s.CreateUsageEvent(ctx, &UsageEvent{UserID: "u1", ProviderID: "google", Action: "token_exchange"})
	s.CreateUsageEvent(ctx, &UsageEvent{UserID: "u1", ProviderID: "google", Action: "token_exchange"})
	s.CreateUsageEvent(ctx, &UsageEvent{UserID: "u2", ProviderID: "google", Action: "token_refresh"})

	stats, err := s.GetUsageStats(ctx, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("GetUsageStats: %v", err)
	}
	if stats["token_exchange"] != 2 {
		t.Errorf("token_exchange = %d, want 2", stats["token_exchange"])
	}
	if stats["token_refresh"] != 1 {
		t.Errorf("token_refresh = %d, want 1", stats["token_refresh"])
	}
}

func TestSQLiteRelaySessionLifecycle(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	sess := &RelaySession{
		SessionID:  "sess-1",
		UserID:     "u1",
		ProviderID: "google",
		State:      "csrf-token-xyz",
		Scopes:     "docs sheets",
		Status:     "pending",
	}
	if err := s.CreateRelaySession(ctx, sess); err != nil {
		t.Fatalf("CreateRelaySession: %v", err)
	}

	// Get by ID
	got, err := s.GetRelaySession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetRelaySession: %v", err)
	}
	if got.State != "csrf-token-xyz" {
		t.Errorf("state = %q", got.State)
	}

	// Get by state
	got, err = s.GetRelaySessionByState(ctx, "csrf-token-xyz")
	if err != nil {
		t.Fatalf("GetRelaySessionByState: %v", err)
	}
	if got.SessionID != "sess-1" {
		t.Errorf("session_id = %q", got.SessionID)
	}

	// Update (complete)
	now := time.Now()
	sess.Status = "completed"
	sess.CompletedAt = &now
	if err = s.UpdateRelaySession(ctx, sess); err != nil {
		t.Fatalf("UpdateRelaySession: %v", err)
	}

	got, err = s.GetRelaySession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetRelaySession after update: %v", err)
	}
	if got.Status != "completed" {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
}

func TestSQLiteRelaySessionCleanExpired(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()

	s.CreateUser(ctx, &User{ID: "u1", Email: "a@b.com", Name: "A", Role: "user"})

	// Create an expired session (created 2 hours ago, still pending)
	sess := &RelaySession{
		SessionID:  "old-sess",
		UserID:     "u1",
		ProviderID: "google",
		State:      "old-state",
		Scopes:     "docs",
		Status:     "pending",
	}
	if err := s.CreateRelaySession(ctx, sess); err != nil {
		t.Fatalf("CreateRelaySession: %v", err)
	}

	// Force the created_at to be old via direct SQL
	s.db.ExecContext(ctx, "UPDATE relay_sessions SET created_at = datetime('now', '-2 hours') WHERE session_id = 'old-sess'")

	cleaned, err := s.CleanExpiredRelaySessions(ctx)
	if err != nil {
		t.Fatalf("CleanExpiredRelaySessions: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1", cleaned)
	}
}
