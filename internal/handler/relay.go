package handler

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/httputil"
	"github.com/piper/oauth-token-relay/internal/provider"
	"github.com/piper/oauth-token-relay/internal/store"
)

const tokenCacheTTL = 5 * time.Minute
const sessionMaxAge = 10 * time.Minute

// tokenEntry holds upstream tokens in memory (never persisted to database).
type tokenEntry struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	CreatedAt    time.Time
}

// RelayHandler handles the token relay flow.
type RelayHandler struct {
	store      store.Store
	registry   *provider.Registry
	tokenCache map[string]*tokenEntry // sessionID → tokens (in-memory only)
	mu         sync.Mutex
}

func NewRelayHandler(st store.Store, reg *provider.Registry) *RelayHandler {
	return &RelayHandler{
		store:      st,
		registry:   reg,
		tokenCache: make(map[string]*tokenEntry),
	}
}

// HandleStart handles POST /auth/tokens/start.
// Requires Bearer auth. Creates a relay session and returns the provider auth URL.
func (h *RelayHandler) HandleStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		Scopes []string `json:"scopes"`
	}
	if err := httputil.ReadJSON(w, r, &req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	prov, err := h.registry.Get(claims.ProviderID)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("provider not found: %s", claims.ProviderID)})
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	sessionID := uuid.NewString()
	sess := &store.RelaySession{
		SessionID:  sessionID,
		UserID:     claims.Subject,
		ProviderID: claims.ProviderID,
		State:      state,
		Scopes:     joinScopes(req.Scopes),
		Status:     "pending",
	}
	if err := h.store.CreateRelaySession(ctx, sess); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	authURL := prov.AuthURL(state, req.Scopes)

	if err := h.store.CreateAuditEntry(ctx, &store.AuditEntry{
		UserID:     claims.Subject,
		ProviderID: claims.ProviderID,
		Action:     "relay_start",
		IPAddress:  r.RemoteAddr,
	}); err != nil {
		log.Printf("audit: %v", err)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"auth_url":   authURL,
		"session_id": sessionID,
	})
}

// HandleCallback handles GET /auth/tokens/callback.
// Browser redirect from the OAuth provider after user authorization.
func (h *RelayHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	sess, err := h.store.GetRelaySessionByState(ctx, state)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}
	if sess.Status != "pending" {
		http.Error(w, "Session already completed", http.StatusConflict)
		return
	}

	// Reject stale sessions (#8) and mark as expired (#2)
	if time.Since(sess.CreatedAt) > sessionMaxAge {
		sess.Status = "expired"
		if err := h.store.UpdateRelaySession(ctx, sess); err != nil {
			log.Printf("relay session update: %v", err)
		}
		http.Error(w, "Session expired", http.StatusGone)
		return
	}

	prov, err := h.registry.Get(sess.ProviderID)
	if err != nil {
		http.Error(w, "Provider not found", http.StatusInternalServerError)
		return
	}

	result, err := prov.Exchange(ctx, code)
	if err != nil {
		// Mark session as expired to prevent replay (#2)
		sess.Status = "expired"
		if updateErr := h.store.UpdateRelaySession(ctx, sess); updateErr != nil {
			log.Printf("relay session update: %v", updateErr)
		}
		http.Error(w, "Token exchange failed", http.StatusBadGateway)
		return
	}

	// Store tokens in memory only — never in the database (#1)
	h.mu.Lock()
	h.tokenCache[sess.SessionID] = &tokenEntry{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		CreatedAt:    time.Now(),
	}
	h.mu.Unlock()

	// Mark session as completed in DB (no tokens stored)
	now := time.Now()
	sess.Status = "completed"
	sess.CompletedAt = &now
	if err := h.store.UpdateRelaySession(ctx, sess); err != nil {
		// Roll back in-memory cache on DB failure
		h.mu.Lock()
		delete(h.tokenCache, sess.SessionID)
		h.mu.Unlock()
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := h.store.CreateAuditEntry(ctx, &store.AuditEntry{
		UserID:     sess.UserID,
		ProviderID: sess.ProviderID,
		Action:     "relay_callback",
	}); err != nil {
		log.Printf("audit: %v", err)
	}
	if err := h.store.CreateUsageEvent(ctx, &store.UsageEvent{
		UserID:     sess.UserID,
		ProviderID: sess.ProviderID,
		Action:     "token_exchange",
	}); err != nil {
		log.Printf("usage: %v", err)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html><html><body><h1>Authorization successful</h1><p>You can close this window and return to the CLI.</p></body></html>`)
}

// HandleComplete handles POST /auth/tokens/complete.
// CLI polls this to retrieve tokens after callback.
func (h *RelayHandler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := httputil.ReadJSON(w, r, &req); err != nil || req.SessionID == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}

	sess, err := h.store.GetRelaySession(ctx, req.SessionID)
	if err != nil {
		httputil.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	if sess.UserID != claims.Subject {
		httputil.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "session belongs to another user"})
		return
	}

	switch sess.Status {
	case "pending":
		httputil.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
	case "completed":
		// Atomic token delivery (#9): take tokens from cache under lock.
		// Only one concurrent request can succeed.
		h.mu.Lock()
		entry, ok := h.tokenCache[sess.SessionID]
		if ok {
			delete(h.tokenCache, sess.SessionID)
		}
		h.mu.Unlock()

		if !ok {
			// Tokens already delivered or expired from cache
			httputil.WriteJSON(w, http.StatusGone, map[string]string{"error": "tokens already delivered or expired"})
			return
		}

		resp := map[string]any{
			"access_token": entry.AccessToken,
			"expires_in":   entry.ExpiresIn,
		}
		if entry.RefreshToken != "" {
			resp["refresh_token"] = entry.RefreshToken
		}
		httputil.WriteJSON(w, http.StatusOK, resp)

		// Mark session as expired in DB
		sess.Status = "expired"
		if err := h.store.UpdateRelaySession(ctx, sess); err != nil {
			log.Printf("relay session cleanup: %v", err)
		}
	case "expired":
		httputil.WriteJSON(w, http.StatusGone, map[string]string{"error": "session expired"})
	default:
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "unknown session status"})
	}
}

// HandleRefresh handles POST /auth/tokens/refresh.
// Refreshes an upstream provider token.
func (h *RelayHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := httputil.ReadJSON(w, r, &req); err != nil || req.RefreshToken == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token required"})
		return
	}

	prov, err := h.registry.Get(claims.ProviderID)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "provider not found"})
		return
	}

	result, err := prov.Refresh(ctx, req.RefreshToken)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadGateway, map[string]string{"error": "refresh failed"})
		return
	}

	if err := h.store.CreateUsageEvent(ctx, &store.UsageEvent{
		UserID:     claims.Subject,
		ProviderID: claims.ProviderID,
		Action:     "token_refresh",
	}); err != nil {
		log.Printf("usage: %v", err)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": result.AccessToken,
		"expires_in":   result.ExpiresIn,
	})
}

// HandleRevoke handles POST /auth/tokens/revoke.
// Revokes an upstream provider token.
func (h *RelayHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := httputil.ReadJSON(w, r, &req); err != nil || req.Token == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "token required"})
		return
	}

	prov, err := h.registry.Get(claims.ProviderID)
	if err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "provider not found"})
		return
	}

	if err := prov.Revoke(ctx, req.Token); err != nil {
		httputil.WriteJSON(w, http.StatusBadGateway, map[string]string{"error": "revoke failed"})
		return
	}

	if err := h.store.CreateAuditEntry(ctx, &store.AuditEntry{
		UserID:     claims.Subject,
		ProviderID: claims.ProviderID,
		Action:     "token_revoke",
		IPAddress:  r.RemoteAddr,
	}); err != nil {
		log.Printf("audit: %v", err)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// CleanExpiredTokenCache removes token cache entries older than the TTL.
// Called periodically or on-demand.
func (h *RelayHandler) CleanExpiredTokenCache() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, entry := range h.tokenCache {
		if time.Since(entry.CreatedAt) > tokenCacheTTL {
			delete(h.tokenCache, id)
		}
	}
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
