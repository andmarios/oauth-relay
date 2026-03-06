package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/store"
)

// adminMockStore embeds mockRelayStore for all stub methods, then overrides
// the ones used by admin handlers with testable in-memory implementations.
type adminMockStore struct {
	mockRelayStore

	users        map[string]*store.User
	providerList []*store.Provider
	auditEntries []*store.AuditEntry
	usageStats   map[string]int64
}

func newAdminMockStore() *adminMockStore {
	return &adminMockStore{
		mockRelayStore: mockRelayStore{
			sessions: make(map[string]*store.RelaySession),
			byState:  make(map[string]*store.RelaySession),
		},
		users:      make(map[string]*store.User),
		usageStats: make(map[string]int64),
	}
}

func (s *adminMockStore) GetUser(_ context.Context, id string) (*store.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return u, nil
}

func (s *adminMockStore) GetProvider(_ context.Context, id string) (*store.Provider, error) {
	for _, p := range s.providerList {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *adminMockStore) ListUsers(_ context.Context, limit, offset int) ([]*store.User, int, error) {
	all := make([]*store.User, 0, len(s.users))
	for _, u := range s.users {
		all = append(all, u)
	}
	total := len(all)
	if offset >= len(all) {
		return nil, total, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

func (s *adminMockStore) UpdateUser(_ context.Context, u *store.User) error {
	s.users[u.ID] = u
	return nil
}

func (s *adminMockStore) DeleteUser(_ context.Context, id string) error {
	if _, ok := s.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.users, id)
	return nil
}

func (s *adminMockStore) DeleteUserRefreshTokens(_ context.Context, _ string) error {
	return nil
}

func (s *adminMockStore) ListAuditEntries(_ context.Context, f *store.AuditFilter) ([]*store.AuditEntry, int, error) {
	filtered := make([]*store.AuditEntry, 0, len(s.auditEntries))
	for _, e := range s.auditEntries {
		if f.UserID != "" && e.UserID != f.UserID {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		filtered = append(filtered, e)
	}
	total := len(filtered)
	if f.Offset >= len(filtered) {
		return nil, total, nil
	}
	end := f.Offset + f.Limit
	if end > len(filtered) || f.Limit == 0 {
		end = len(filtered)
	}
	return filtered[f.Offset:end], total, nil
}

func (s *adminMockStore) GetUsageStats(_ context.Context, _ time.Time) (map[string]int64, error) {
	return s.usageStats, nil
}

func (s *adminMockStore) ListProviders(_ context.Context) ([]*store.Provider, error) {
	return s.providerList, nil
}

// Interface compliance
var _ store.Store = (*adminMockStore)(nil)

// --- Test helpers ---

func adminJWTService() *auth.JWTService {
	return auth.NewJWTService("test-secret-key-256-bits-long!!", "test", time.Hour, 24*time.Hour)
}

func adminAuthRequest(t *testing.T, method, url string, body *bytes.Buffer) (*http.Request, *auth.JWTService) {
	t.Helper()
	jwtSvc := adminJWTService()
	token, _ := jwtSvc.IssueAccessToken("admin-1", "admin@test.com", "admin", "google")
	if body == nil {
		body = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, url, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, jwtSvc
}

func serveAdmin(handler http.HandlerFunc, req *http.Request, jwtSvc *auth.JWTService) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mw := auth.RequireAdmin(jwtSvc)
	mw(handler).ServeHTTP(rr, req)
	return rr
}

// --- Tests ---

func TestAdminListUsers(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1", Email: "a@test.com", Role: "user"}
	st.users["u2"] = &store.User{ID: "u2", Email: "b@test.com", Role: "admin"}
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/users?limit=10", nil)
	rr := serveAdmin(h.HandleListUsers, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["total"].(float64) != 2 {
		t.Errorf("total = %v, want 2", resp["total"])
	}
}

func TestAdminListUsersRequiresAdmin(t *testing.T) {
	st := newAdminMockStore()
	h := NewAdminHandler(st)

	// Authenticate as regular user (not admin)
	jwtSvc := adminJWTService()
	token, _ := jwtSvc.IssueAccessToken("user-1", "user@test.com", "user", "google")
	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw := auth.RequireAdmin(jwtSvc)
	mw(http.HandlerFunc(h.HandleListUsers)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestAdminGetUser(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1", Email: "a@test.com", Role: "user"}
	st.auditEntries = []*store.AuditEntry{
		{UserID: "u1", Action: "login"},
		{UserID: "u1", Action: "relay_start"},
		{UserID: "u2", Action: "login"}, // different user
	}
	h := NewAdminHandler(st)

	// Use Go 1.22 path value pattern
	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/users/u1", nil)
	req.SetPathValue("id", "u1")
	rr := serveAdmin(h.HandleGetUser, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	user := resp["user"].(map[string]any)
	if user["ID"] != "u1" {
		t.Errorf("user ID = %v, want u1", user["ID"])
	}
	audit := resp["audit"].([]any)
	if len(audit) != 2 {
		t.Errorf("audit entries = %d, want 2 (filtered to u1)", len(audit))
	}
}

func TestAdminGetUserNotFound(t *testing.T) {
	st := newAdminMockStore()
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/users/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rr := serveAdmin(h.HandleGetUser, req, jwtSvc)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestAdminDeleteUser(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1", Email: "a@test.com"}
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "DELETE", "/admin/users/u1", nil)
	req.SetPathValue("id", "u1")
	rr := serveAdmin(h.HandleDeleteUser, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	if _, ok := st.users["u1"]; ok {
		t.Error("user u1 should have been deleted")
	}
}

func TestAdminAssignProvider(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1", Email: "a@test.com", ProviderID: "old"}
	st.providerList = []*store.Provider{{ID: "google", DisplayName: "Google"}}
	h := NewAdminHandler(st)

	body := jsonBody(t, map[string]string{"provider_id": "google"})
	req, jwtSvc := adminAuthRequest(t, "POST", "/admin/users/u1/assign-provider", body)
	req.SetPathValue("id", "u1")
	rr := serveAdmin(h.HandleAssignProvider, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	if st.users["u1"].ProviderID != "google" {
		t.Errorf("provider_id = %q, want google", st.users["u1"].ProviderID)
	}
}

func TestAdminAssignProviderInvalidProvider(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1", Email: "a@test.com"}
	// No providers configured — "nonexistent" won't match
	h := NewAdminHandler(st)

	body := jsonBody(t, map[string]string{"provider_id": "nonexistent"})
	req, jwtSvc := adminAuthRequest(t, "POST", "/admin/users/u1/assign-provider", body)
	req.SetPathValue("id", "u1")
	rr := serveAdmin(h.HandleAssignProvider, req, jwtSvc)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestAdminAssignProviderMissingBody(t *testing.T) {
	st := newAdminMockStore()
	st.users["u1"] = &store.User{ID: "u1"}
	h := NewAdminHandler(st)

	body := jsonBody(t, map[string]string{})
	req, jwtSvc := adminAuthRequest(t, "POST", "/admin/users/u1/assign-provider", body)
	req.SetPathValue("id", "u1")
	rr := serveAdmin(h.HandleAssignProvider, req, jwtSvc)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestAdminUsageStats(t *testing.T) {
	st := newAdminMockStore()
	st.usageStats = map[string]int64{
		"token_exchange": 42,
		"token_refresh":  10,
	}
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/usage", nil)
	rr := serveAdmin(h.HandleUsageStats, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	stats := resp["stats"].(map[string]any)
	if stats["token_exchange"].(float64) != 42 {
		t.Errorf("token_exchange = %v, want 42", stats["token_exchange"])
	}
}

func TestAdminAuditLog(t *testing.T) {
	st := newAdminMockStore()
	st.auditEntries = []*store.AuditEntry{
		{UserID: "u1", Action: "login"},
		{UserID: "u1", Action: "relay_start"},
		{UserID: "u2", Action: "login"},
	}
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/audit?user_id=u1", nil)
	rr := serveAdmin(h.HandleAuditLog, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["total"].(float64) != 2 {
		t.Errorf("total = %v, want 2 (filtered to u1)", resp["total"])
	}
}

func TestAdminListProviders(t *testing.T) {
	st := newAdminMockStore()
	st.providerList = []*store.Provider{
		{ID: "google", DisplayName: "Google Corp"},
		{ID: "github", DisplayName: "GitHub"},
	}
	h := NewAdminHandler(st)

	req, jwtSvc := adminAuthRequest(t, "GET", "/admin/providers", nil)
	rr := serveAdmin(h.HandleListProviders, req, jwtSvc)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	providers := resp["providers"].([]any)
	if len(providers) != 2 {
		t.Errorf("providers count = %d, want 2", len(providers))
	}
}
