package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/provider"
	"github.com/piper/oauth-token-relay/internal/store"
)

// --- Mock Provider ---

type mockProvider struct {
	id             string
	displayName    string
	authURLBase    string
	exchangeResult *provider.TokenResult
	exchangeErr    error
	refreshResult  *provider.TokenResult
	refreshErr     error
	revokeErr      error
}

func (m *mockProvider) ID() string          { return m.id }
func (m *mockProvider) DisplayName() string { return m.displayName }
func (m *mockProvider) AuthURL(state string, scopes []string) string {
	return m.authURLBase + "?state=" + state
}
func (m *mockProvider) Exchange(_ context.Context, _ string) (*provider.TokenResult, error) {
	return m.exchangeResult, m.exchangeErr
}
func (m *mockProvider) Refresh(_ context.Context, _ string) (*provider.TokenResult, error) {
	return m.refreshResult, m.refreshErr
}
func (m *mockProvider) Revoke(_ context.Context, _ string) error {
	return m.revokeErr
}

// --- Mock Store (relay-focused) ---

type mockRelayStore struct {
	sessions map[string]*store.RelaySession
	byState  map[string]*store.RelaySession

	createErr error
	getErr    error
	updateErr error
}

func newMockRelayStore() *mockRelayStore {
	return &mockRelayStore{
		sessions: make(map[string]*store.RelaySession),
		byState:  make(map[string]*store.RelaySession),
	}
}

func (s *mockRelayStore) CreateRelaySession(_ context.Context, sess *store.RelaySession) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.sessions[sess.SessionID] = sess
	s.byState[sess.State] = sess
	return nil
}

func (s *mockRelayStore) GetRelaySession(_ context.Context, sessionID string) (*store.RelaySession, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func (s *mockRelayStore) GetRelaySessionByState(_ context.Context, state string) (*store.RelaySession, error) {
	sess, ok := s.byState[state]
	if !ok {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func (s *mockRelayStore) UpdateRelaySession(_ context.Context, sess *store.RelaySession) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.sessions[sess.SessionID] = sess
	return nil
}

func (s *mockRelayStore) CreateAuditEntry(_ context.Context, _ *store.AuditEntry) error { return nil }
func (s *mockRelayStore) CreateUsageEvent(_ context.Context, _ *store.UsageEvent) error { return nil }
func (s *mockRelayStore) Close() error                                                  { return nil }
func (s *mockRelayStore) Migrate(_ context.Context) error                               { return nil }
func (s *mockRelayStore) CreateUser(_ context.Context, _ *store.User) error             { return nil }
func (s *mockRelayStore) GetUser(_ context.Context, _ string) (*store.User, error)      { return nil, nil }
func (s *mockRelayStore) GetUserByEmail(_ context.Context, _ string) (*store.User, error) {
	return nil, nil
}
func (s *mockRelayStore) ListUsers(_ context.Context, _, _ int) ([]*store.User, int, error) {
	return nil, 0, nil
}
func (s *mockRelayStore) UpdateUser(_ context.Context, _ *store.User) error         { return nil }
func (s *mockRelayStore) DeleteUser(_ context.Context, _ string) error              { return nil }
func (s *mockRelayStore) UpdateLastLogin(_ context.Context, _ string) error         { return nil }
func (s *mockRelayStore) UpsertProvider(_ context.Context, _ *store.Provider) error { return nil }
func (s *mockRelayStore) GetProvider(_ context.Context, _ string) (*store.Provider, error) {
	return nil, nil
}
func (s *mockRelayStore) ListProviders(_ context.Context) ([]*store.Provider, error) { return nil, nil }
func (s *mockRelayStore) DeleteProvider(_ context.Context, _ string) error           { return nil }
func (s *mockRelayStore) CreateRefreshToken(_ context.Context, _ *store.RefreshToken) error {
	return nil
}
func (s *mockRelayStore) GetRefreshToken(_ context.Context, _ string) (*store.RefreshToken, error) {
	return nil, nil
}
func (s *mockRelayStore) DeleteRefreshToken(_ context.Context, _ string) error      { return nil }
func (s *mockRelayStore) DeleteUserRefreshTokens(_ context.Context, _ string) error { return nil }
func (s *mockRelayStore) CleanExpiredRefreshTokens(_ context.Context) (int64, error) {
	return 0, nil
}
func (s *mockRelayStore) CreateAuthCode(_ context.Context, _ *store.AuthCode) error { return nil }
func (s *mockRelayStore) GetAuthCode(_ context.Context, _ string) (*store.AuthCode, error) {
	return nil, nil
}
func (s *mockRelayStore) DeleteAuthCode(_ context.Context, _ string) error              { return nil }
func (s *mockRelayStore) CleanExpiredAuthCodes(_ context.Context) (int64, error)        { return 0, nil }
func (s *mockRelayStore) CreateDeviceCode(_ context.Context, _ *store.DeviceCode) error { return nil }
func (s *mockRelayStore) GetDeviceCode(_ context.Context, _ string) (*store.DeviceCode, error) {
	return nil, nil
}
func (s *mockRelayStore) GetDeviceCodeByUserCode(_ context.Context, _ string) (*store.DeviceCode, error) {
	return nil, nil
}
func (s *mockRelayStore) UpdateDeviceCode(_ context.Context, _ *store.DeviceCode) error { return nil }
func (s *mockRelayStore) CleanExpiredDeviceCodes(_ context.Context) (int64, error)      { return 0, nil }
func (s *mockRelayStore) ListAuditEntries(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, int, error) {
	return nil, 0, nil
}
func (s *mockRelayStore) GetUsageStats(_ context.Context, _ time.Time) (map[string]int64, error) {
	return nil, nil
}
func (s *mockRelayStore) CleanExpiredRelaySessions(_ context.Context) (int64, error) { return 0, nil }

// Interface compliance
var _ store.Store = (*mockRelayStore)(nil)

// --- Test helpers ---

func testClaims(subject, providerID string) *auth.Claims {
	return &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ProviderID: providerID,
		TokenType:  "access",
	}
}

func testRelayHandler() (*RelayHandler, *mockRelayStore, *mockProvider) {
	st := newMockRelayStore()
	prov := &mockProvider{
		id:          "google",
		displayName: "Google",
		authURLBase: "https://accounts.google.com/o/oauth2/v2/auth",
	}
	reg := provider.NewRegistryFromProviders(map[string]provider.Provider{
		"google": prov,
	})
	h := NewRelayHandler(st, reg)
	return h, st, prov
}

func jsonBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

// --- Tests ---

func TestHandleStartSuccess(t *testing.T) {
	h, _, prov := testRelayHandler()
	prov.authURLBase = "https://accounts.google.com/auth"

	claims := testClaims("user-1", "google")
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)

	body := jsonBody(t, map[string]any{"scopes": []string{"read", "write"}})
	req := httptest.NewRequest("POST", "/auth/tokens/start", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleStart)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	resp := decodeJSON(t, rr)
	if resp["auth_url"] == nil || resp["auth_url"] == "" {
		t.Error("expected auth_url in response")
	}
	if resp["session_id"] == nil || resp["session_id"] == "" {
		t.Error("expected session_id in response")
	}
}

func TestHandleStartUnauthorized(t *testing.T) {
	h, _, _ := testRelayHandler()

	body := jsonBody(t, map[string]any{"scopes": []string{"read"}})
	req := httptest.NewRequest("POST", "/auth/tokens/start", body)
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header
	rr := httptest.NewRecorder()
	h.HandleStart(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestHandleStartProviderNotFound(t *testing.T) {
	h, _, _ := testRelayHandler()

	claims := testClaims("user-1", "unknown-provider")
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)

	body := jsonBody(t, map[string]any{"scopes": []string{"read"}})
	req := httptest.NewRequest("POST", "/auth/tokens/start", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleStart)).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleCallbackSuccess(t *testing.T) {
	h, st, prov := testRelayHandler()
	prov.exchangeResult = &provider.TokenResult{
		AccessToken:  "upstream-access-token",
		RefreshToken: "upstream-refresh-token",
		ExpiresIn:    3600,
	}

	// Pre-create a pending session (with recent CreatedAt for TTL check)
	sess := &store.RelaySession{
		SessionID:  "sess-1",
		UserID:     "user-1",
		ProviderID: "google",
		State:      "test-state-123",
		Status:     "pending",
		CreatedAt:  time.Now(),
	}
	st.sessions[sess.SessionID] = sess
	st.byState[sess.State] = sess

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=auth-code-xyz&state=test-state-123", nil)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	// Verify session status updated in DB (tokens NOT in DB)
	updated := st.sessions["sess-1"]
	if updated.Status != "completed" {
		t.Errorf("session status = %q, want completed", updated.Status)
	}
	if updated.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	// Session in DB should have no token fields (removed from struct)

	// Verify tokens are in the in-memory cache
	h.mu.Lock()
	entry, ok := h.tokenCache["sess-1"]
	h.mu.Unlock()
	if !ok {
		t.Fatal("expected tokens in in-memory cache")
	}
	if entry.AccessToken != "upstream-access-token" {
		t.Errorf("cached access token = %q, want upstream-access-token", entry.AccessToken)
	}
}

func TestHandleCallbackMissingParams(t *testing.T) {
	h, _, _ := testRelayHandler()

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=abc", nil) // missing state
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleCallbackInvalidState(t *testing.T) {
	h, _, _ := testRelayHandler()

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=abc&state=unknown", nil)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestHandleCallbackAlreadyCompleted(t *testing.T) {
	h, st, _ := testRelayHandler()

	sess := &store.RelaySession{
		SessionID: "sess-1",
		UserID:    "user-1",
		State:     "test-state",
		Status:    "completed",
	}
	st.sessions[sess.SessionID] = sess
	st.byState[sess.State] = sess

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=abc&state=test-state", nil)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rr.Code)
	}
}

func TestHandleCallbackExchangeFailed(t *testing.T) {
	h, st, prov := testRelayHandler()
	prov.exchangeErr = errors.New("upstream error")

	sess := &store.RelaySession{
		SessionID:  "sess-1",
		UserID:     "user-1",
		ProviderID: "google",
		State:      "test-state",
		Status:     "pending",
		CreatedAt:  time.Now(),
	}
	st.sessions[sess.SessionID] = sess
	st.byState[sess.State] = sess

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=abc&state=test-state", nil)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}

func TestHandleCallbackStaleSession(t *testing.T) {
	h, st, _ := testRelayHandler()

	sess := &store.RelaySession{
		SessionID:  "sess-1",
		UserID:     "user-1",
		ProviderID: "google",
		State:      "test-state",
		Status:     "pending",
		CreatedAt:  time.Now().Add(-15 * time.Minute), // 15 min ago — exceeds 10 min TTL
	}
	st.sessions[sess.SessionID] = sess
	st.byState[sess.State] = sess

	req := httptest.NewRequest("GET", "/auth/tokens/callback?code=abc&state=test-state", nil)
	rr := httptest.NewRecorder()
	h.HandleCallback(rr, req)

	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 (stale session)", rr.Code)
	}
}

func TestHandleCompletePending(t *testing.T) {
	h, st, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	sess := &store.RelaySession{
		SessionID: "sess-1",
		UserID:    "user-1",
		Status:    "pending",
	}
	st.sessions[sess.SessionID] = sess

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req := httptest.NewRequest("POST", "/auth/tokens/complete", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body = %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCompleteSuccess(t *testing.T) {
	h, st, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	now := time.Now()
	sess := &store.RelaySession{
		SessionID:   "sess-1",
		UserID:      "user-1",
		Status:      "completed",
		CompletedAt: &now,
	}
	st.sessions[sess.SessionID] = sess

	// Place tokens in the in-memory cache (as HandleCallback would)
	h.mu.Lock()
	h.tokenCache["sess-1"] = &tokenEntry{
		AccessToken:  "upstream-at",
		RefreshToken: "upstream-rt",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
	}
	h.mu.Unlock()

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req := httptest.NewRequest("POST", "/auth/tokens/complete", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	resp := decodeJSON(t, rr)
	if resp["access_token"] != "upstream-at" {
		t.Errorf("access_token = %v, want upstream-at", resp["access_token"])
	}
	if resp["refresh_token"] != "upstream-rt" {
		t.Errorf("refresh_token = %v, want upstream-rt", resp["refresh_token"])
	}

	// Verify tokens removed from cache after delivery
	h.mu.Lock()
	_, cached := h.tokenCache["sess-1"]
	h.mu.Unlock()
	if cached {
		t.Error("tokens should be removed from cache after delivery")
	}

	// Verify session marked expired in DB
	if st.sessions["sess-1"].Status != "expired" {
		t.Errorf("session status = %q, want expired", st.sessions["sess-1"].Status)
	}
}

func TestHandleCompleteDoubleDelivery(t *testing.T) {
	h, st, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	now := time.Now()
	sess := &store.RelaySession{
		SessionID:   "sess-1",
		UserID:      "user-1",
		Status:      "completed",
		CompletedAt: &now,
	}
	st.sessions[sess.SessionID] = sess

	// Place tokens in cache
	h.mu.Lock()
	h.tokenCache["sess-1"] = &tokenEntry{
		AccessToken: "upstream-at",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}
	h.mu.Unlock()

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)

	// First request — should succeed
	body1 := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req1 := httptest.NewRequest("POST", "/auth/tokens/complete", body1)
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+token)
	rr1 := httptest.NewRecorder()
	auth.RequireAuth(jwtSvc)(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", rr1.Code)
	}

	// Second request — tokens already delivered, should get 410
	// Reset session status to "completed" to test the cache-miss path
	// (In production, first request sets it to "expired", so second gets 410 from that branch.
	// But even if status is still "completed", missing cache entry → 410.)
	st.sessions["sess-1"].Status = "completed"
	body2 := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req2 := httptest.NewRequest("POST", "/auth/tokens/complete", body2)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+token)
	rr2 := httptest.NewRecorder()
	auth.RequireAuth(jwtSvc)(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusGone {
		t.Errorf("second request: status = %d, want 410 (already delivered)", rr2.Code)
	}
}

func TestHandleCompleteWrongUser(t *testing.T) {
	h, st, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	sess := &store.RelaySession{
		SessionID: "sess-1",
		UserID:    "user-1",
		Status:    "completed",
	}
	st.sessions[sess.SessionID] = sess

	// Authenticated as user-2, trying to access user-1's session
	claims := testClaims("user-2", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req := httptest.NewRequest("POST", "/auth/tokens/complete", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestHandleCompleteExpired(t *testing.T) {
	h, st, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	sess := &store.RelaySession{
		SessionID: "sess-1",
		UserID:    "user-1",
		Status:    "expired",
	}
	st.sessions[sess.SessionID] = sess

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"session_id": "sess-1"})
	req := httptest.NewRequest("POST", "/auth/tokens/complete", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleComplete)).ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", rr.Code)
	}
}

func TestHandleRefreshSuccess(t *testing.T) {
	h, _, prov := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
	prov.refreshResult = &provider.TokenResult{
		AccessToken: "new-access-token",
		ExpiresIn:   3600,
	}

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"refresh_token": "old-refresh-token"})
	req := httptest.NewRequest("POST", "/auth/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleRefresh)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	resp := decodeJSON(t, rr)
	if resp["access_token"] != "new-access-token" {
		t.Errorf("access_token = %v, want new-access-token", resp["access_token"])
	}
}

func TestHandleRefreshUpstreamError(t *testing.T) {
	h, _, prov := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
	prov.refreshErr = errors.New("upstream refresh failed")

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"refresh_token": "old-refresh-token"})
	req := httptest.NewRequest("POST", "/auth/tokens/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleRefresh)).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}

func TestHandleRevokeSuccess(t *testing.T) {
	h, _, _ := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"token": "some-upstream-token"})
	req := httptest.NewRequest("POST", "/auth/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleRevoke)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}

func TestCleanExpiredTokenCache(t *testing.T) {
	h, _, _ := testRelayHandler()

	// Add one expired and one fresh entry
	h.mu.Lock()
	h.tokenCache["expired-sess"] = &tokenEntry{
		AccessToken: "old",
		CreatedAt:   time.Now().Add(-10 * time.Minute), // well past 5-min TTL
	}
	h.tokenCache["fresh-sess"] = &tokenEntry{
		AccessToken: "new",
		CreatedAt:   time.Now(),
	}
	h.mu.Unlock()

	h.CleanExpiredTokenCache()

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.tokenCache["expired-sess"]; ok {
		t.Error("expired entry should have been cleaned")
	}
	if _, ok := h.tokenCache["fresh-sess"]; !ok {
		t.Error("fresh entry should still exist")
	}
}

func TestHandleRevokeUpstreamError(t *testing.T) {
	h, _, prov := testRelayHandler()
	jwtSvc := auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
	prov.revokeErr = errors.New("upstream revoke failed")

	claims := testClaims("user-1", "google")
	token, _ := jwtSvc.IssueAccessToken(claims.Subject, claims.Email, claims.Role, claims.ProviderID)
	body := jsonBody(t, map[string]string{"token": "some-upstream-token"})
	req := httptest.NewRequest("POST", "/auth/tokens/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAuth(jwtSvc)
	mw(http.HandlerFunc(h.HandleRevoke)).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}
