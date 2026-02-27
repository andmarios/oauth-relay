package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/piper/oauth-token-relay/internal/auth"
)

func testOAuth21Server(t *testing.T) *auth.OAuth21Server {
	t.Helper()
	srv, err := auth.NewOAuth21Server(auth.OAuth21Config{
		Issuer:    "http://localhost:8080",
		SecretKey: []byte("test-secret-key-256-bits-long!!!!"), // 32 bytes
		Clients: []*auth.OAuth21Client{
			{
				ID:            "cli",
				Public:        true,
				RedirectURIs:  []string{"http://localhost:9999/callback"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "offline"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOAuth21Server: %v", err)
	}
	return srv
}

func testSessionManager(t *testing.T) *auth.SessionManager {
	t.Helper()
	sm, err := auth.NewSessionManager([]byte("test-session-key-for-unit-tests"), false)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	return sm
}

func TestHandleAuthorizeNoSession(t *testing.T) {
	oauthSrv := testOAuth21Server(t)
	sm := testSessionManager(t)
	h := NewOAuthHandler(oauthSrv, nil, nil, sm, time.Hour, 30*24*time.Hour)

	// No login session cookie — should redirect to /oauth/login
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id=cli&response_type=code", nil)
	rr := httptest.NewRecorder()
	h.HandleAuthorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth/login") {
		t.Errorf("expected redirect to /oauth/login, got %q", location)
	}
}

func TestHandleTokenMissingGrantType(t *testing.T) {
	oauthSrv := testOAuth21Server(t)
	sm := testSessionManager(t)
	h := NewOAuthHandler(oauthSrv, nil, nil, sm, time.Hour, 30*24*time.Hour)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	// Missing grant_type should return 400 unsupported_grant_type
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing grant_type, got %d", rr.Code)
	}
}

func TestHandleTokenInvalidCode(t *testing.T) {
	oauthSrv := testOAuth21Server(t)
	sm := testSessionManager(t)
	h := NewOAuthHandler(oauthSrv, nil, nil, sm, time.Hour, 30*24*time.Hour)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"cli"},
		"code_verifier": {"test-verifier-that-is-long-enough-to-be-valid-43-chars"},
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for invalid code, got %d", rr.Code)
	}
}

func TestHandleTokenRefreshMissing(t *testing.T) {
	oauthSrv := testOAuth21Server(t)
	sm := testSessionManager(t)
	h := NewOAuthHandler(oauthSrv, nil, nil, sm, time.Hour, 30*24*time.Hour)

	form := url.Values{
		"grant_type": {"refresh_token"},
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	// Missing refresh_token param should return 400
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing refresh_token, got %d", rr.Code)
	}
}

func TestHandleRevokeEmptyToken(t *testing.T) {
	oauthSrv := testOAuth21Server(t)
	sm := testSessionManager(t)
	h := NewOAuthHandler(oauthSrv, nil, nil, sm, time.Hour, 30*24*time.Hour)

	// Empty token — RFC 7009 says always return 200
	req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleRevoke(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for revoke, got %d", rr.Code)
	}
}
