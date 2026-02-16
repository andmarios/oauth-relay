package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/piper/oauth-token-relay/internal/auth"
)

func testOAuth21Server() *auth.OAuth21Server {
	return auth.NewOAuth21Server(auth.OAuth21Config{
		Issuer:    "http://localhost:8080",
		SecretKey: []byte("test-secret-key-256-bits-long!!"),
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
}

func TestHandleAuthorizeMissingParams(t *testing.T) {
	oauthSrv := testOAuth21Server()
	h := NewOAuthHandler(oauthSrv, nil, nil)

	// Missing client_id, redirect_uri, etc.
	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	rr := httptest.NewRecorder()
	h.HandleAuthorize(rr, req)

	// Fosite returns 302 redirect with error or writes error directly
	// Without proper params, it should not return 200
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for missing params, got %d", rr.Code)
	}
}

func TestHandleTokenMissingGrantType(t *testing.T) {
	oauthSrv := testOAuth21Server()
	h := NewOAuthHandler(oauthSrv, nil, nil)

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleToken(rr, req)

	// Missing grant_type should fail
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for missing grant_type, got %d", rr.Code)
	}
}

func TestHandleTokenInvalidCode(t *testing.T) {
	oauthSrv := testOAuth21Server()
	h := NewOAuthHandler(oauthSrv, nil, nil)

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

func TestHandleRevoke(t *testing.T) {
	oauthSrv := testOAuth21Server()
	h := NewOAuthHandler(oauthSrv, nil, nil)

	form := url.Values{"token": {"some-token"}}
	req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.HandleRevoke(rr, req)

	// Fosite returns 200 for valid-format tokens not found, 400 for unparseable tokens.
	// Both are acceptable — handler doesn't panic and responds with JSON.
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 200 or 400", rr.Code)
	}
}
