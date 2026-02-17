package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/store"
)

// mockLoginStore embeds mockRelayStore for all stub methods, then overrides
// the ones used by LoginHandler with testable in-memory implementations.
type mockLoginStore struct {
	mockRelayStore
	users       map[string]*store.User
	lastLoginID string
}

func (m *mockLoginStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockLoginStore) UpdateLastLogin(_ context.Context, id string) error {
	m.lastLoginID = id
	return nil
}

// Interface compliance
var _ store.Store = (*mockLoginStore)(nil)

func newTestLoginHandler(t *testing.T) (*LoginHandler, *mockLoginStore) {
	t.Helper()
	sessionMgr, err := auth.NewSessionManager([]byte("test-key-32-bytes-for-testing!!!"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	mockStore := &mockLoginStore{
		mockRelayStore: mockRelayStore{
			sessions: make(map[string]*store.RelaySession),
			byState:  make(map[string]*store.RelaySession),
		},
		users: map[string]*store.User{
			"u1": {
				ID:         "u1",
				Email:      "admin@example.com",
				Name:       "Admin User",
				Role:       "admin",
				ProviderID: "google-corp",
			},
		},
	}

	return NewLoginHandler(mockStore, sessionMgr), mockStore
}

func TestLoginPageRenders(t *testing.T) {
	h, _ := newTestLoginHandler(t)

	req := httptest.NewRequest("GET", "/oauth/login?return_to=/oauth/authorize%3Fclient_id%3Dcli", nil)
	w := httptest.NewRecorder()
	h.HandleLoginPage(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Sign In") {
		t.Error("expected login form")
	}
	if !strings.Contains(body, "return_to") {
		t.Error("expected return_to hidden field")
	}
}

func TestLoginSubmitValidEmail(t *testing.T) {
	h, mockStore := newTestLoginHandler(t)

	form := url.Values{
		"email":     {"admin@example.com"},
		"return_to": {"/oauth/authorize?client_id=cli"},
	}
	req := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleLoginSubmit(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/oauth/authorize") {
		t.Errorf("Location = %q, want redirect to /oauth/authorize...", loc)
	}

	// Check session cookie was set
	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_otr_session" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie")
	}

	// Check last login was updated
	if mockStore.lastLoginID != "u1" {
		t.Errorf("lastLoginID = %q, want u1", mockStore.lastLoginID)
	}
}

func TestLoginSubmitUnknownEmail(t *testing.T) {
	h, _ := newTestLoginHandler(t)

	form := url.Values{
		"email":     {"unknown@example.com"},
		"return_to": {"/oauth/authorize"},
	}
	req := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleLoginSubmit(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (re-render form)", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "not recognized") {
		t.Error("expected error message about unrecognized email")
	}
}

func TestLoginSubmitEmptyEmail(t *testing.T) {
	h, _ := newTestLoginHandler(t)

	form := url.Values{
		"email":     {""},
		"return_to": {"/oauth/authorize"},
	}
	req := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleLoginSubmit(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "required") {
		t.Error("expected error about email being required")
	}
}

func TestLoginSubmitInvalidReturnTo(t *testing.T) {
	h, _ := newTestLoginHandler(t)

	form := url.Values{
		"email":     {"admin@example.com"},
		"return_to": {"https://evil.com/steal"},
	}
	req := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.HandleLoginSubmit(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid return_to", resp.StatusCode)
	}
}

func TestIsValidReturnTo(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"/oauth/authorize", true},
		{"/oauth/authorize?client_id=cli", true},
		{"https://evil.com", false},
		{"/admin/users", false},
		{"//evil.com", false},
		{"javascript:alert(1)", false},
	}
	for _, tt := range tests {
		if got := isValidReturnTo(tt.input); got != tt.want {
			t.Errorf("isValidReturnTo(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
