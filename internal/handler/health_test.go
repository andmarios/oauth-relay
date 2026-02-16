package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/piper/oauth-token-relay/internal/config"
	"github.com/piper/oauth-token-relay/internal/provider"
)

func testRegistry() *provider.Registry {
	return provider.NewRegistry(map[string]config.ProviderConfig{
		"google-corp": {
			DisplayName:  "Google Corp",
			ClientID:     "gid",
			ClientSecret: "gsecret",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
		},
	}, "http://localhost:8080")
}

func TestHealthHandler(t *testing.T) {
	h := NewHealthHandler(testRegistry())

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	providers, ok := body["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Errorf("providers = %v, want 1 item", body["providers"])
	}
}
