package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/idp"
	"github.com/piper/oauth-token-relay/internal/store"
)

// --- Mocks ---

type mockIdentityProvider struct {
	id            string
	displayName   string
	authURL       string
	exchangeToken string
	exchangeErr   error
	userInfo      *idp.UserInfo
	userInfoErr   error
}

func (m *mockIdentityProvider) ID() string          { return m.id }
func (m *mockIdentityProvider) DisplayName() string { return m.displayName }
func (m *mockIdentityProvider) AuthURL(state string) string {
	return m.authURL + "?state=" + state
}
func (m *mockIdentityProvider) Exchange(_ context.Context, _ string) (string, error) {
	return m.exchangeToken, m.exchangeErr
}
func (m *mockIdentityProvider) GetUserInfo(_ context.Context, _ string) (*idp.UserInfo, error) {
	return m.userInfo, m.userInfoErr
}

type mockSSOStore struct {
	store.Store
	users        map[string]*store.User
	createdUsers []*store.User
	providers    []*store.Provider
}

func newMockSSOStore() *mockSSOStore {
	return &mockSSOStore{users: make(map[string]*store.User)}
}

func (s *mockSSOStore) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *mockSSOStore) CreateUser(_ context.Context, u *store.User) error {
	s.users[u.ID] = u
	s.createdUsers = append(s.createdUsers, u)
	return nil
}

func (s *mockSSOStore) UpdateLastLogin(_ context.Context, _ string) error {
	return nil
}

func (s *mockSSOStore) ListProviders(_ context.Context) ([]*store.Provider, error) {
	return s.providers, nil
}

func (s *mockSSOStore) UpdateUser(_ context.Context, u *store.User) error {
	s.users[u.ID] = u
	return nil
}

// --- Helpers ---

func ssoSessionMgr(t *testing.T, opts ...auth.SessionOption) *auth.SessionManager {
	t.Helper()
	sm, err := auth.NewSessionManager([]byte("test-key-for-sso-handler-test!!"), false, opts...)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	return sm
}

func setupSSOHandler(t *testing.T, st *mockSSOStore, mockIDP *mockIdentityProvider, bootstrapAdmins []string) (*SSOHandler, *auth.SessionManager) {
	t.Helper()
	oauthSM := ssoSessionMgr(t)
	adminSM := ssoSessionMgr(t, auth.WithCookieName("_otr_admin"), auth.WithPath("/admin/"), auth.WithTTL(8*time.Hour))
	ssoSM := ssoSessionMgr(t, auth.WithCookieName("_otr_sso"), auth.WithPath("/"), auth.WithTTL(10*time.Minute))

	reg := idp.NewRegistryFromProviders(map[string]idp.IdentityProvider{
		mockIDP.ID(): mockIDP,
	})

	h := NewSSOHandler(st, oauthSM, adminSM, ssoSM, reg, bootstrapAdmins)
	return h, ssoSM
}

// --- Tests ---

func TestHandleLoginPageOAuth(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google", authURL: "https://accounts.google.com/auth"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/oauth/login?return_to=/oauth/authorize%3Fclient_id%3Dcli", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign in with Google") {
		t.Error("expected 'Sign in with Google' button in HTML")
	}
	if !strings.Contains(body, "Sign In") {
		t.Error("expected 'Sign In' title")
	}
	if !strings.Contains(body, "/sso/start/google") {
		t.Error("expected link to /sso/start/google")
	}
}

func TestHandleLoginPageAdmin(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/admin/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Admin Sign In") {
		t.Error("expected 'Admin Sign In' title")
	}
}

func TestHandleLoginPageInvalidReturnTo(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	// return_to pointing to external URL should be rejected
	req := httptest.NewRequest("GET", "/oauth/login?return_to=https://evil.com", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid return_to, got %d", rr.Code)
	}
}

func TestHandleLoginPageErrorMessage(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/oauth/login?error=Something+went+wrong", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginPage(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Something went wrong") {
		t.Error("expected error message in HTML")
	}
}

func TestHandleSSOStartRedirect(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google", authURL: "https://accounts.google.com/auth"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/sso/start/google?return_to=/oauth/authorize", nil)
	req.SetPathValue("provider", "google")
	rr := httptest.NewRecorder()
	h.HandleSSOStart(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "https://accounts.google.com/auth") {
		t.Errorf("expected redirect to Google auth, got %q", location)
	}
	if !strings.Contains(location, "state=") {
		t.Error("expected state parameter in redirect URL")
	}
	// Should set SSO cookie
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_otr_sso" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected _otr_sso cookie to be set")
	}
}

func TestHandleSSOStartUnknownProvider(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/sso/start/unknown?return_to=/oauth/authorize", nil)
	req.SetPathValue("provider", "unknown")
	rr := httptest.NewRecorder()
	h.HandleSSOStart(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown provider, got %d", rr.Code)
	}
}

func TestHandleSSOStartInvalidReturnTo(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", displayName: "Google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	req := httptest.NewRequest("GET", "/sso/start/google?return_to=https://evil.com", nil)
	req.SetPathValue("provider", "google")
	rr := httptest.NewRecorder()
	h.HandleSSOStart(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid return_to, got %d", rr.Code)
	}
}

func TestHandleSSOCallbackFullFlow(t *testing.T) {
	st := newMockSSOStore()
	st.users["existing-id"] = &store.User{ID: "existing-id", Email: "user@example.com", Name: "User", Role: "user"}

	mockP := &mockIdentityProvider{
		id:            "google",
		displayName:   "Google",
		authURL:       "https://accounts.google.com/auth",
		exchangeToken: "access-token-123",
		userInfo:      &idp.UserInfo{Email: "user@example.com", Name: "User"},
	}
	h, ssoSM := setupSSOHandler(t, st, mockP, nil)

	// Simulate the SSO state cookie that HandleSSOStart would create
	state := "test-state-nonce"
	returnTo := "/oauth/authorize?client_id=cli"

	// Create a request and set the SSO cookie
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      state,
		ReturnTo:   returnTo,
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	// Now make the callback request
	callbackURL := fmt.Sprintf("/sso/callback?code=auth-code&state=%s", url.QueryEscape(state))
	req := httptest.NewRequest("GET", callbackURL, nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	if rr2.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr2.Code)
	}
	location := rr2.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/authorize") {
		t.Errorf("expected redirect to /oauth/authorize, got %q", location)
	}
}

func TestHandleSSOCallbackAutoProvision(t *testing.T) {
	st := newMockSSOStore() // empty store — no users

	mockP := &mockIdentityProvider{
		id:            "google",
		exchangeToken: "access-token",
		userInfo:      &idp.UserInfo{Email: "new@example.com", Name: "New User"},
	}
	h, ssoSM := setupSSOHandler(t, st, mockP, nil)

	// Create SSO cookie
	state := "state-abc"
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      state,
		ReturnTo:   "/oauth/authorize",
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	// Callback
	req := httptest.NewRequest("GET", "/sso/callback?code=code&state="+state, nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	if rr2.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr2.Code)
	}
	// Verify user was auto-provisioned
	if len(st.createdUsers) != 1 {
		t.Fatalf("expected 1 created user, got %d", len(st.createdUsers))
	}
	u := st.createdUsers[0]
	if u.Email != "new@example.com" {
		t.Errorf("created user email = %q, want %q", u.Email, "new@example.com")
	}
	if u.Role != "user" {
		t.Errorf("created user role = %q, want %q", u.Role, "user")
	}
}

func TestHandleSSOCallbackBootstrapAdmin(t *testing.T) {
	st := newMockSSOStore()

	mockP := &mockIdentityProvider{
		id:            "google",
		exchangeToken: "token",
		userInfo:      &idp.UserInfo{Email: "admin@example.com", Name: "Admin"},
	}
	h, ssoSM := setupSSOHandler(t, st, mockP, []string{"admin@example.com"})

	state := "state-admin"
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      state,
		ReturnTo:   "/admin/",
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/sso/callback?code=code&state="+state, nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	if rr2.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr2.Code)
	}
	// Verify user was created as admin
	if len(st.createdUsers) != 1 {
		t.Fatalf("expected 1 created user, got %d", len(st.createdUsers))
	}
	if st.createdUsers[0].Role != "admin" {
		t.Errorf("bootstrap admin role = %q, want %q", st.createdUsers[0].Role, "admin")
	}
}

func TestHandleSSOCallbackNonAdminDenied(t *testing.T) {
	st := newMockSSOStore()
	st.users["user-1"] = &store.User{ID: "user-1", Email: "user@example.com", Role: "user"}

	mockP := &mockIdentityProvider{
		id:            "google",
		exchangeToken: "token",
		userInfo:      &idp.UserInfo{Email: "user@example.com"},
	}
	h, ssoSM := setupSSOHandler(t, st, mockP, nil)

	state := "state-nonadmin"
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      state,
		ReturnTo:   "/admin/",
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/sso/callback?code=code&state="+state, nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	// Non-admin trying to access admin should be redirected with error
	if rr2.Code != http.StatusFound {
		t.Errorf("expected 302 redirect with error, got %d", rr2.Code)
	}
	location := rr2.Header().Get("Location")
	if !strings.Contains(location, "error=") {
		t.Errorf("expected error in redirect, got %q", location)
	}
}

func TestHandleSSOCallbackStateMismatch(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google", exchangeToken: "token", userInfo: &idp.UserInfo{Email: "a@b.com"}}
	h, ssoSM := setupSSOHandler(t, st, mockP, nil)

	// Create cookie with one state
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      "correct-state",
		ReturnTo:   "/oauth/authorize",
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	// But send a different state in the URL
	req := httptest.NewRequest("GET", "/sso/callback?code=code&state=wrong-state", nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	if rr2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for state mismatch, got %d", rr2.Code)
	}
}

func TestHandleSSOCallbackMissingParams(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	// Missing code
	req := httptest.NewRequest("GET", "/sso/callback?state=abc", nil)
	rr := httptest.NewRecorder()
	h.HandleSSOCallback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", rr.Code)
	}

	// Missing state
	req2 := httptest.NewRequest("GET", "/sso/callback?code=abc", nil)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing state, got %d", rr2.Code)
	}
}

func TestHandleSSOCallbackExchangeError(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{
		id:          "google",
		exchangeErr: fmt.Errorf("provider error"),
	}
	h, ssoSM := setupSSOHandler(t, st, mockP, nil)

	state := "state-err"
	rr := httptest.NewRecorder()
	ssoSM.Create(rr, &auth.SessionData{
		State:      state,
		ReturnTo:   "/oauth/authorize",
		ProviderID: "google",
	})
	ssoCookie := rr.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/sso/callback?code=code&state="+state, nil)
	req.AddCookie(ssoCookie)
	rr2 := httptest.NewRecorder()
	h.HandleSSOCallback(rr2, req)

	// Should redirect to login with error
	if rr2.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr2.Code)
	}
	loc := rr2.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("expected error in redirect, got %q", loc)
	}
}

func TestHandleSSOCallbackIDPError(t *testing.T) {
	st := newMockSSOStore()
	mockP := &mockIdentityProvider{id: "google"}
	h, _ := setupSSOHandler(t, st, mockP, nil)

	// IDP redirects back with error (user denied consent)
	req := httptest.NewRequest("GET", "/sso/callback?error=access_denied&error_description=User+denied+access", nil)
	rr := httptest.NewRecorder()
	h.HandleSSOCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("expected error in redirect, got %q", loc)
	}
	if !strings.Contains(loc, "User+denied+access") && !strings.Contains(loc, "User%20denied%20access") {
		t.Errorf("expected error description in redirect, got %q", loc)
	}
}

func TestIsValidSSOReturnTo(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"/oauth/authorize", true},
		{"/oauth/login", true},
		{"/admin/", true},
		{"/admin/users", true},
		{"https://evil.com", false},
		{"/other/path", false},
		{"javascript:alert(1)", false},
		{"//evil.com", false},
	}
	for _, tt := range tests {
		got := isValidSSOReturnTo(tt.input)
		if got != tt.want {
			t.Errorf("isValidSSOReturnTo(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
