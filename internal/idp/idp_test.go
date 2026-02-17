package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewOAuth2IdentityProvider(t *testing.T) {
	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:           "google",
		DisplayName:  "Google",
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:       []string{"openid", "email"},
		EmailField:   "email",
		RedirectURL:  "http://localhost:8080/sso/callback",
	})

	if p.ID() != "google" {
		t.Errorf("ID = %q, want %q", p.ID(), "google")
	}
	if p.DisplayName() != "Google" {
		t.Errorf("DisplayName = %q, want %q", p.DisplayName(), "Google")
	}
}

func TestAuthURL(t *testing.T) {
	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:           "google",
		ClientID:     "test-client",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		Scopes:       []string{"openid", "email"},
		RedirectURL:  "http://localhost:8080/sso/callback",
	})

	authURL := p.AuthURL("test-state-123")
	if !strings.Contains(authURL, "accounts.google.com") {
		t.Errorf("AuthURL should contain authorize endpoint, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=test-state-123") {
		t.Errorf("AuthURL should contain state parameter, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=test-client") {
		t.Errorf("AuthURL should contain client_id, got %q", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=") {
		t.Errorf("AuthURL should contain redirect_uri, got %q", authURL)
	}
}

func TestGetUserInfoStandardOIDC(t *testing.T) {
	// Mock userinfo endpoint returning standard OIDC object
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer token is sent
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %q", auth)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"email": "user@example.com",
			"name":  "Test User",
		})
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "test",
		UserInfoURL: srv.URL,
		EmailField:  "email",
	})

	info, err := p.GetUserInfo(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("GetUserInfo error: %v", err)
	}
	if info.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "user@example.com")
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q, want %q", info.Name, "Test User")
	}
}

func TestGetUserInfoCustomEmailField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"mail": "custom@example.com",
			"name": "Custom",
		})
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "test",
		UserInfoURL: srv.URL,
		EmailField:  "mail",
	})

	info, err := p.GetUserInfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("GetUserInfo error: %v", err)
	}
	if info.Email != "custom@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "custom@example.com")
	}
}

func TestGetUserInfoGitHubEmails(t *testing.T) {
	// Mock GitHub /user/emails endpoint returning array
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]githubEmail{
			{Email: "noreply@github.com", Primary: false, Verified: true},
			{Email: "user@example.com", Primary: true, Verified: true},
		})
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "github",
		UserInfoURL: srv.URL,
		EmailField:  "email",
	})

	info, err := p.GetUserInfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("GetUserInfo error: %v", err)
	}
	if info.Email != "user@example.com" {
		t.Errorf("Email = %q, want primary email %q", info.Email, "user@example.com")
	}
}

func TestGetUserInfoGitHubNoVerifiedEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]githubEmail{
			{Email: "unverified@example.com", Primary: true, Verified: false},
		})
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "github",
		UserInfoURL: srv.URL,
	})

	_, err := p.GetUserInfo(context.Background(), "token")
	if err == nil {
		t.Error("expected error for no verified GitHub emails")
	}
}

func TestGetUserInfoMissingEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"name": "No Email User",
		})
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "test",
		UserInfoURL: srv.URL,
		EmailField:  "email",
	})

	_, err := p.GetUserInfo(context.Background(), "token")
	if err == nil {
		t.Error("expected error for missing email field")
	}
}

func TestGetUserInfoHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	p := NewOAuth2IdentityProvider(OAuth2IDPConfig{
		ID:          "test",
		UserInfoURL: srv.URL,
	})

	_, err := p.GetUserInfo(context.Background(), "bad-token")
	if err == nil {
		t.Error("expected error for HTTP 401")
	}
}

func TestRegistryGetAndList(t *testing.T) {
	// Build a registry with pre-built providers using a simpler approach
	p1 := NewOAuth2IdentityProvider(OAuth2IDPConfig{ID: "google", DisplayName: "Google"})
	p2 := NewOAuth2IdentityProvider(OAuth2IDPConfig{ID: "github", DisplayName: "GitHub"})

	r := &Registry{providers: map[string]IdentityProvider{
		"google": p1,
		"github": p2,
	}}

	// Test Get
	got, err := r.Get("google")
	if err != nil {
		t.Fatalf("Get('google') error: %v", err)
	}
	if got.ID() != "google" {
		t.Errorf("got ID %q, want %q", got.ID(), "google")
	}

	// Test Get unknown
	_, err = r.Get("unknown")
	if err == nil {
		t.Error("expected error for unknown provider")
	}

	// Test List
	list := r.List()
	if len(list) != 2 {
		t.Errorf("List() returned %d providers, want 2", len(list))
	}
}
