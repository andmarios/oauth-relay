package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ory/fosite"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/httputil"
	"github.com/piper/oauth-token-relay/internal/store"
)

// pendingCode holds an authorization code waiting for CLI pickup.
type pendingCode struct {
	code      string
	createdAt time.Time
}

// OAuthHandler handles OAuth 2.1 AS endpoints (PKCE authorization code flow).
type OAuthHandler struct {
	oauth      *auth.OAuth21Server
	jwt        *auth.JWTService
	store      store.Store
	session    *auth.SessionManager
	accessTTL  time.Duration
	refreshTTL time.Duration

	// pendingCodes stores authorization codes keyed by state, for CLI polling.
	pendingMu    sync.Mutex
	pendingCodes map[string]pendingCode
}

func NewOAuthHandler(oauth *auth.OAuth21Server, jwt *auth.JWTService, st store.Store, session *auth.SessionManager, accessTTL, refreshTTL time.Duration) *OAuthHandler {
	return &OAuthHandler{
		oauth:        oauth,
		jwt:          jwt,
		store:        st,
		session:      session,
		accessTTL:    accessTTL,
		refreshTTL:   refreshTTL,
		pendingCodes: make(map[string]pendingCode),
	}
}

// HandleAuthorize handles GET /oauth/authorize — PKCE authorization endpoint.
// Requires a valid login session. Redirects to /oauth/login if not authenticated.
func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for login session
	sessionData, err := h.session.Get(r)
	if err != nil {
		// No valid session — redirect to login
		returnTo := r.URL.RequestURI()
		http.Redirect(w, r, "/oauth/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Parse and validate Fosite authorize request
	ar, err := h.oauth.Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.oauth.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Grant requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Create Fosite session with authenticated user identity
	session := newFositeSession(sessionData.UserID)
	resp, err := h.oauth.Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.oauth.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Clear login session — it was only needed for the authorize step
	h.session.Clear(w)

	h.oauth.Provider.WriteAuthorizeResponse(ctx, w, ar, resp)
}

// HandleToken handles POST /oauth/token — code exchange and refresh.
// For authorization_code: validates via Fosite, then issues server JWTs.
// For refresh_token: validates server JWT directly, issues new JWTs.
func (h *OAuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleCodeExchange(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	default:
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("grant type %q is not supported", grantType),
		})
	}
}

// handleCodeExchange handles grant_type=authorization_code.
// Uses Fosite to validate the auth code + PKCE, then issues server JWTs.
func (h *OAuthHandler) handleCodeExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Let Fosite validate the authorization code and PKCE
	session := newFositeSession("")
	ar, err := h.oauth.Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.oauth.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Complete the Fosite flow (cleans up auth code, creates Fosite tokens)
	// We'll discard Fosite's tokens and issue our own JWTs.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	_, err = h.oauth.Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		h.oauth.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Extract user ID from the Fosite session subject
	fositeSession, ok := ar.GetSession().(*fosite.DefaultSession)
	if !ok || fositeSession.Subject == "" {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "missing user identity in authorization session",
		})
		return
	}

	// Look up user for current claims
	user, err := h.store.GetUser(ctx, fositeSession.Subject)
	if err != nil {
		log.Printf("oauth token: user lookup: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "user not found",
		})
		return
	}

	// Issue server JWTs
	h.issueAndWriteTokens(w, r, user)
}

// handleRefreshToken handles grant_type=refresh_token with server JWTs.
// Validates the JWT refresh token, checks revocation, and issues new tokens.
func (h *OAuthHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	refreshTokenStr := r.PostFormValue("refresh_token")
	if refreshTokenStr == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "refresh_token is required",
		})
		return
	}

	// Validate JWT signature and expiry
	claims, err := h.jwt.ValidateToken(refreshTokenStr)
	if err != nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid or expired refresh token",
		})
		return
	}

	if claims.TokenType != "refresh" {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_grant",
			"error_description": "token is not a refresh token",
		})
		return
	}

	// Delete old refresh token atomically (rotation) — if not found, it was revoked
	tokenHash := hashToken(refreshTokenStr)
	if err := h.store.DeleteRefreshToken(ctx, tokenHash); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, `{"error":"invalid_grant","error_description":"refresh token has been revoked"}`, http.StatusBadRequest)
			return
		}
		log.Printf("oauth refresh: delete token: %v", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	// Look up user for fresh claims
	user, err := h.store.GetUser(ctx, claims.Subject)
	if err != nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_grant",
			"error_description": "user not found",
		})
		return
	}

	// Issue new tokens
	h.issueAndWriteTokens(w, r, user)
}

// issueAndWriteTokens creates server JWTs and writes the token response.
func (h *OAuthHandler) issueAndWriteTokens(w http.ResponseWriter, r *http.Request, user *store.User) {
	ctx := r.Context()

	accessToken, err := h.jwt.IssueAccessToken(user.ID, user.Email, user.Role, user.ProviderID)
	if err != nil {
		log.Printf("oauth: issue access token: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
		return
	}

	refreshToken, _, err := h.jwt.IssueRefreshToken(user.ID)
	if err != nil {
		log.Printf("oauth: issue refresh token: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
		return
	}

	// Store refresh token hash for revocation tracking
	if err := h.store.CreateRefreshToken(ctx, &store.RefreshToken{
		TokenHash: hashToken(refreshToken),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(h.refreshTTL),
	}); err != nil {
		log.Printf("oauth: store refresh token: %v", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	// Audit
	if err := h.store.CreateAuditEntry(ctx, &store.AuditEntry{
		UserID:     user.ID,
		ProviderID: user.ProviderID,
		Action:     "server_token_issued",
		IPAddress:  r.RemoteAddr,
	}); err != nil {
		log.Printf("oauth: audit: %v", err)
	}

	// Write standard OAuth token response
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "bearer",
		"expires_in":    int(h.accessTTL.Seconds()),
		"refresh_token": refreshToken,
	})
}

// HandleRevoke handles POST /oauth/revoke — token revocation.
func (h *OAuthHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var tokenStr string
	if r.Header.Get("Content-Type") == "application/json" {
		var req struct {
			Token string `json:"token"`
		}
		if err := httputil.ReadJSON(w, r, &req); err == nil {
			tokenStr = req.Token
		}
	} else {
		tokenStr = r.PostFormValue("token")
	}

	if tokenStr != "" {
		// Try to delete as refresh token
		tokenHash := hashToken(tokenStr)
		if err := h.store.DeleteRefreshToken(ctx, tokenHash); err != nil {
			log.Printf("oauth revoke: %v", err)
		}
	}

	// RFC 7009: always return 200
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleCLICallback handles GET /oauth/cli-callback — stores the authorization code
// for CLI polling pickup. The browser shows a success message.
func (h *OAuthHandler) HandleCLICallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing authorization code or state", http.StatusBadRequest)
		return
	}

	// Store code for CLI to pick up via polling
	h.pendingMu.Lock()
	h.pendingCodes[state] = pendingCode{
		code:      code,
		createdAt: time.Now(),
	}
	h.pendingMu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", cspWithFonts)
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Complete — OAuth Token Relay</title>
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <link rel="stylesheet" href="/static/login.css">
</head>
<body>
    <div class="card">
        <div class="success-icon">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
                <defs>
                    <linearGradient id="sg" x1="8" y1="8" x2="56" y2="56" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#34d399"/>
                        <stop offset="100%" stop-color="#059669"/>
                    </linearGradient>
                </defs>
                <circle class="circle" cx="32" cy="32" r="27" stroke="url(#sg)" stroke-width="2.5" fill="rgba(52,211,153,0.08)"/>
                <path class="check" d="M20 33l8 8 16-18" stroke="url(#sg)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
            </svg>
        </div>
        <h1>Authorization Complete</h1>
        <p class="desc">You can close this tab and return to your terminal.</p>
        <p class="desc">The CLI is picking up the authorization automatically.</p>
    </div>
    <div class="footer">OAuth Token Relay</div>
</body>
</html>`)
}

// HandleCLIPoll handles GET /oauth/cli-poll — CLI polls for the authorization code.
// Returns 200 with {"code":"..."} if available, or 202 with {"status":"pending"}.
//
// Security model: the state parameter is 32 bytes of crypto/rand (256 bits),
// making it unguessable. Codes are deleted on first retrieval (one-time use)
// and expire after 10 minutes. Even if an attacker obtained the auth code via
// polling, the PKCE code_verifier (held only by the legitimate CLI) is required
// to exchange it for tokens. Per-IP rate limiting further mitigates brute-force.
// This matches the pattern used by GitHub CLI, Azure CLI, and similar tools.
func (h *OAuthHandler) HandleCLIPoll(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing state parameter",
		})
		return
	}

	h.pendingMu.Lock()
	pending, ok := h.pendingCodes[state]
	if ok {
		delete(h.pendingCodes, state)
	}
	h.pendingMu.Unlock()

	if !ok {
		httputil.WriteJSON(w, http.StatusAccepted, map[string]string{
			"status": "pending",
		})
		return
	}

	// Check if code has expired (10 minute TTL)
	if time.Since(pending.createdAt) > 10*time.Minute {
		httputil.WriteJSON(w, http.StatusGone, map[string]string{
			"error": "authorization code expired",
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"code": pending.code,
	})
}

// CleanExpiredPendingCodes removes pending codes older than 10 minutes.
func (h *OAuthHandler) CleanExpiredPendingCodes() {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	for state, pc := range h.pendingCodes {
		if time.Since(pc.createdAt) > 10*time.Minute {
			delete(h.pendingCodes, state)
		}
	}
}

func newFositeSession(subject string) *fosite.DefaultSession {
	return &fosite.DefaultSession{
		Subject: subject,
	}
}

// hashToken computes SHA-256 of a token string for storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
