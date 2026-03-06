package provider

import (
	"strings"
	"testing"

	"github.com/piper/oauth-token-relay/internal/config"
)

func TestOAuth2ProviderAuthURL(t *testing.T) {
	p := NewOAuth2Provider(&OAuth2Config{
		ID:           "google-corp",
		DisplayName:  "Google Corp",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		RedirectURL:  "http://localhost:8080/auth/tokens/callback",
		ExtraParams: map[string]string{
			"access_type": "offline",
			"prompt":      "consent",
		},
	})

	if p.ID() != "google-corp" {
		t.Errorf("ID = %q", p.ID())
	}
	if p.DisplayName() != "Google Corp" {
		t.Errorf("DisplayName = %q", p.DisplayName())
	}

	authURL := p.AuthURL("test-state", []string{"https://www.googleapis.com/auth/documents"})

	if !strings.Contains(authURL, "accounts.google.com") {
		t.Errorf("auth URL missing domain: %s", authURL)
	}
	if !strings.Contains(authURL, "state=test-state") {
		t.Errorf("auth URL missing state: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=client-id") {
		t.Errorf("auth URL missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "access_type=offline") {
		t.Errorf("auth URL missing extra param access_type: %s", authURL)
	}
	if !strings.Contains(authURL, "prompt=consent") {
		t.Errorf("auth URL missing extra param prompt: %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=") {
		t.Errorf("auth URL missing redirect_uri: %s", authURL)
	}
}

func TestRegistryFromConfig(t *testing.T) {
	providers := map[string]config.ProviderConfig{
		"google-corp": {
			DisplayName:  "Google Corp",
			ClientID:     "gid",
			ClientSecret: "gsecret",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
		},
		"microsoft": {
			DisplayName:  "Microsoft",
			ClientID:     "mid",
			ClientSecret: "msecret",
			AuthorizeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
	}

	reg := NewRegistry(providers, "http://localhost:8080")

	ids := reg.List()
	if len(ids) != 2 {
		t.Errorf("len = %d, want 2", len(ids))
	}

	p, err := reg.Get("google-corp")
	if err != nil {
		t.Fatalf("Get google-corp: %v", err)
	}
	if p.DisplayName() != "Google Corp" {
		t.Errorf("DisplayName = %q", p.DisplayName())
	}

	_, err = reg.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}
