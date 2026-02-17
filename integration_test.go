//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/handler"
	"github.com/piper/oauth-token-relay/internal/provider"
	"github.com/piper/oauth-token-relay/internal/server"
	"github.com/piper/oauth-token-relay/internal/store"
)

// mockIntegrationProvider is a test provider that returns canned tokens.
type mockIntegrationProvider struct{}

func (m *mockIntegrationProvider) ID() string          { return "test-provider" }
func (m *mockIntegrationProvider) DisplayName() string { return "Test Provider" }
func (m *mockIntegrationProvider) AuthURL(state string, _ []string) string {
	return "http://localhost/fake-auth?state=" + state
}
func (m *mockIntegrationProvider) Exchange(_ context.Context, _ string) (*provider.TokenResult, error) {
	return &provider.TokenResult{
		AccessToken:  "integration-access-token",
		RefreshToken: "integration-refresh-token",
		ExpiresIn:    3600,
	}, nil
}
func (m *mockIntegrationProvider) Refresh(_ context.Context, _ string) (*provider.TokenResult, error) {
	return &provider.TokenResult{
		AccessToken: "refreshed-access-token",
		ExpiresIn:   3600,
	}, nil
}
func (m *mockIntegrationProvider) Revoke(_ context.Context, _ string) error {
	return nil
}

func setupIntegrationServer(t *testing.T) (string, *auth.JWTService, store.Store) {
	t.Helper()

	// Create SQLite store
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	st, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Create test user
	if err := st.CreateUser(ctx, &store.User{
		ID:         "test-user-1",
		Email:      "test@example.com",
		Name:       "Test User",
		Role:       "admin",
		ProviderID: "test-provider",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Sync provider to DB
	st.UpsertProvider(ctx, &store.Provider{
		ID:          "test-provider",
		DisplayName: "Test Provider",
		Config:      []byte(`{}`),
	})

	// Build services
	jwtSvc := auth.NewJWTService("integration-test-key-32-chars!!", "test-issuer", time.Hour, 24*time.Hour)
	registry := provider.NewRegistryFromProviders(map[string]provider.Provider{
		"test-provider": &mockIntegrationProvider{},
	})

	// Build handlers
	healthH := handler.NewHealthHandler(registry)
	relayH := handler.NewRelayHandler(st, registry)
	adminH := handler.NewAdminHandler(st)

	// Wire routes
	mux := http.NewServeMux()
	mux.Handle("GET /health", healthH)

	authMW := auth.RequireAuth(jwtSvc)
	adminMW := auth.RequireAdmin(jwtSvc)

	mux.Handle("POST /auth/tokens/start", authMW(http.HandlerFunc(relayH.HandleStart)))
	mux.HandleFunc("GET /auth/tokens/callback", relayH.HandleCallback)
	mux.Handle("POST /auth/tokens/complete", authMW(http.HandlerFunc(relayH.HandleComplete)))
	mux.Handle("POST /auth/tokens/refresh", authMW(http.HandlerFunc(relayH.HandleRefresh)))
	mux.Handle("POST /auth/tokens/revoke", authMW(http.HandlerFunc(relayH.HandleRevoke)))

	mux.Handle("GET /admin/users", adminMW(http.HandlerFunc(adminH.HandleListUsers)))
	mux.Handle("GET /admin/usage", adminMW(http.HandlerFunc(adminH.HandleUsageStats)))
	mux.Handle("GET /admin/audit", adminMW(http.HandlerFunc(adminH.HandleAuditLog)))

	// Start server
	srv := server.New(server.Config{
		Address:         ":0", // Random port
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		ShutdownTimeout: 2 * time.Second,
	}, mux)

	srvCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := srv.Start(srvCtx); err != nil {
			// Only log if not caused by test cleanup
			select {
			case <-srvCtx.Done():
			default:
				t.Logf("server error: %v", err)
			}
		}
	}()

	addr := srv.Addr()
	baseURL := "http://" + addr

	return baseURL, jwtSvc, st
}

func TestIntegrationHealth(t *testing.T) {
	baseURL, _, _ := setupIntegrationServer(t)

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
}

func TestIntegrationTokenRelayFlow(t *testing.T) {
	baseURL, jwtSvc, _ := setupIntegrationServer(t)

	// Get an auth token
	token, err := jwtSvc.IssueAccessToken("test-user-1", "test@example.com", "admin", "test-provider")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Step 1: Start relay
	startBody, _ := json.Marshal(map[string]any{"scopes": []string{"read", "write"}})
	startReq, _ := http.NewRequest("POST", baseURL+"/auth/tokens/start", bytes.NewReader(startBody))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "Bearer "+token)

	startResp, err := http.DefaultClient.Do(startReq)
	if err != nil {
		t.Fatalf("POST /auth/tokens/start: %v", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("start status = %d, body = %s", startResp.StatusCode, body)
	}

	var startResult map[string]any
	json.NewDecoder(startResp.Body).Decode(&startResult)
	authURL := startResult["auth_url"].(string)
	sessionID := startResult["session_id"].(string)

	if authURL == "" {
		t.Error("expected auth_url")
	}
	if sessionID == "" {
		t.Error("expected session_id")
	}

	// Step 2: Poll before callback — should return 202 (pending)
	pollBody, _ := json.Marshal(map[string]string{"session_id": sessionID})
	pollReq, _ := http.NewRequest("POST", baseURL+"/auth/tokens/complete", bytes.NewReader(pollBody))
	pollReq.Header.Set("Content-Type", "application/json")
	pollReq.Header.Set("Authorization", "Bearer "+token)

	pollResp, _ := http.DefaultClient.Do(pollReq)
	pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusAccepted {
		t.Errorf("poll before callback: status = %d, want 202", pollResp.StatusCode)
	}

	// Step 3: Simulate callback (extract state from auth URL)
	// Parse state from the auth URL
	state := ""
	if idx := len("http://localhost/fake-auth?state="); len(authURL) > idx {
		state = authURL[idx:]
	}

	callbackResp, err := http.Get(fmt.Sprintf("%s/auth/tokens/callback?code=test-code&state=%s", baseURL, state))
	if err != nil {
		t.Fatalf("GET /auth/tokens/callback: %v", err)
	}
	callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", callbackResp.StatusCode)
	}

	// Step 4: Complete — should return tokens
	completeBody, _ := json.Marshal(map[string]string{"session_id": sessionID})
	completeReq, _ := http.NewRequest("POST", baseURL+"/auth/tokens/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.Header.Set("Authorization", "Bearer "+token)

	completeResp, _ := http.DefaultClient.Do(completeReq)
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(completeResp.Body)
		t.Fatalf("complete status = %d, body = %s", completeResp.StatusCode, body)
	}

	var completeResult map[string]any
	json.NewDecoder(completeResp.Body).Decode(&completeResult)
	if completeResult["access_token"] != "integration-access-token" {
		t.Errorf("access_token = %v, want integration-access-token", completeResult["access_token"])
	}
	if completeResult["refresh_token"] != "integration-refresh-token" {
		t.Errorf("refresh_token = %v, want integration-refresh-token", completeResult["refresh_token"])
	}

	// Step 5: Second complete — should get 410 (already delivered)
	complete2Body, _ := json.Marshal(map[string]string{"session_id": sessionID})
	complete2Req, _ := http.NewRequest("POST", baseURL+"/auth/tokens/complete", bytes.NewReader(complete2Body))
	complete2Req.Header.Set("Content-Type", "application/json")
	complete2Req.Header.Set("Authorization", "Bearer "+token)

	complete2Resp, _ := http.DefaultClient.Do(complete2Req)
	complete2Resp.Body.Close()
	if complete2Resp.StatusCode != http.StatusGone {
		t.Errorf("second complete: status = %d, want 410", complete2Resp.StatusCode)
	}
}

func TestIntegrationTokenRefresh(t *testing.T) {
	baseURL, jwtSvc, _ := setupIntegrationServer(t)

	token, _ := jwtSvc.IssueAccessToken("test-user-1", "test@example.com", "admin", "test-provider")

	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": "old-refresh-token"})
	req, _ := http.NewRequest("POST", baseURL+"/auth/tokens/refresh", bytes.NewReader(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/tokens/refresh: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["access_token"] != "refreshed-access-token" {
		t.Errorf("access_token = %v, want refreshed-access-token", result["access_token"])
	}
}

func TestIntegrationAdminEndpoints(t *testing.T) {
	baseURL, jwtSvc, _ := setupIntegrationServer(t)

	token, _ := jwtSvc.IssueAccessToken("test-user-1", "test@example.com", "admin", "test-provider")

	// List users
	req, _ := http.NewRequest("GET", baseURL+"/admin/users?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/users: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["total"].(float64) != 1 {
		t.Errorf("total users = %v, want 1", result["total"])
	}
}

func TestIntegrationAuditTrail(t *testing.T) {
	baseURL, jwtSvc, _ := setupIntegrationServer(t)

	token, _ := jwtSvc.IssueAccessToken("test-user-1", "test@example.com", "admin", "test-provider")

	// Perform a relay start to generate audit entries
	startBody, _ := json.Marshal(map[string]any{"scopes": []string{"read"}})
	startReq, _ := http.NewRequest("POST", baseURL+"/auth/tokens/start", bytes.NewReader(startBody))
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "Bearer "+token)
	startResp, _ := http.DefaultClient.Do(startReq)
	startResp.Body.Close()

	// Check audit log
	auditReq, _ := http.NewRequest("GET", baseURL+"/admin/audit?user_id=test-user-1", nil)
	auditReq.Header.Set("Authorization", "Bearer "+token)
	auditResp, _ := http.DefaultClient.Do(auditReq)
	defer auditResp.Body.Close()

	if auditResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(auditResp.Body)
		t.Fatalf("status = %d, body = %s", auditResp.StatusCode, body)
	}

	var result map[string]any
	json.NewDecoder(auditResp.Body).Decode(&result)
	total := result["total"].(float64)
	if total < 1 {
		t.Errorf("expected at least 1 audit entry, got %v", total)
	}
}
