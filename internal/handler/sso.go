package handler

import (
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/idp"
	"github.com/piper/oauth-token-relay/internal/store"
)

// SSOHandler handles SSO-based authentication for both OAuth and admin login flows.
type SSOHandler struct {
	store           store.Store
	oauthSession    *auth.SessionManager // _otr_session, path /oauth/, 10min TTL
	adminSession    *auth.SessionManager // _otr_admin, path /admin/, 8h TTL
	ssoSession      *auth.SessionManager // _otr_sso, path /, 10min TTL — stores SSO state
	idpRegistry     *idp.Registry
	bootstrapAdmins []string
}

// NewSSOHandler creates a new SSO handler.
func NewSSOHandler(
	st store.Store,
	oauthSession *auth.SessionManager,
	adminSession *auth.SessionManager,
	ssoSession *auth.SessionManager,
	idpRegistry *idp.Registry,
	bootstrapAdmins []string,
) *SSOHandler {
	return &SSOHandler{
		store:           st,
		oauthSession:    oauthSession,
		adminSession:    adminSession,
		ssoSession:      ssoSession,
		idpRegistry:     idpRegistry,
		bootstrapAdmins: bootstrapAdmins,
	}
}

// HandleLoginPage renders GET /oauth/login or GET /admin/login with SSO provider buttons.
func (h *SSOHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !isValidSSOReturnTo(returnTo) {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}
	if returnTo == "" {
		// Default based on which login page was requested
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			returnTo = "/admin/"
		} else {
			returnTo = "/oauth/authorize"
		}
	}

	providers := h.idpRegistry.List()
	// Sort for deterministic button order
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].ID() < providers[j].ID()
	})

	isAdmin := strings.HasPrefix(r.URL.Path, "/admin/")
	title := "Sign In"
	subtitle := "Sign in to authorize the CLI"
	if isAdmin {
		title = "Admin Sign In"
		subtitle = "Sign in to access the admin dashboard"
	}

	// Render HTML login page with SSO buttons
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	errMsg := r.URL.Query().Get("error")
	errorHTML := ""
	if errMsg != "" {
		errorHTML = fmt.Sprintf(`<div style="color:#dc3545;background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;padding:10px 15px;margin-bottom:20px">%s</div>`, html.EscapeString(errMsg))
	}

	var buttons strings.Builder
	for _, p := range providers {
		buttons.WriteString(fmt.Sprintf(
			`<a href="/sso/start/%s?return_to=%s" style="display:block;width:100%%;padding:12px;background:#0066cc;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer;text-align:center;text-decoration:none;margin-bottom:12px;box-sizing:border-box">Sign in with %s</a>`,
			html.EscapeString(p.ID()),
			url.QueryEscape(returnTo),
			html.EscapeString(p.DisplayName()),
		))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s — OAuth Token Relay</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 40px; width: 100%%; max-width: 400px; }
        h1 { font-size: 24px; margin-bottom: 8px; color: #333; }
        p.subtitle { color: #666; margin-bottom: 24px; font-size: 14px; }
        a:hover { opacity: 0.9; }
    </style>
</head>
<body>
    <div class="card">
        <h1>%s</h1>
        <p class="subtitle">%s</p>
        %s
        %s
    </div>
</body>
</html>`,
		html.EscapeString(title),
		html.EscapeString(title),
		html.EscapeString(subtitle),
		errorHTML,
		buttons.String(),
	)
}

// HandleSSOStart handles GET /sso/start/{provider} — redirects to the identity provider.
func (h *SSOHandler) HandleSSOStart(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	if providerID == "" {
		http.Error(w, "Missing provider", http.StatusBadRequest)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if !isValidSSOReturnTo(returnTo) {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}
	if returnTo == "" {
		returnTo = "/oauth/authorize"
	}

	provider, err := h.idpRegistry.Get(providerID)
	if err != nil {
		http.Error(w, "Unknown identity provider", http.StatusNotFound)
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		log.Printf("sso: generate state: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Store SSO state in encrypted cookie (provider, return_to, state nonce)
	if err := h.ssoSession.Create(w, &auth.SessionData{
		UserID:     state,      // Repurpose UserID field for state nonce
		Email:      returnTo,   // Repurpose Email field for return_to
		ProviderID: providerID, // Provider ID
	}); err != nil {
		log.Printf("sso: create state cookie: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
}

// HandleSSOCallback handles GET /sso/callback — the identity provider redirects here after user consent.
func (h *SSOHandler) HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for IDP error response (e.g., user denied consent)
	if idpErr := r.URL.Query().Get("error"); idpErr != "" {
		h.ssoSession.Clear(w)
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = "Authentication was cancelled or denied."
		}
		// Determine return path from Referer or default to OAuth login
		loginPath := "/oauth/login"
		if referer := r.Header.Get("Referer"); strings.Contains(referer, "/admin/") {
			loginPath = "/admin/login"
		}
		target := fmt.Sprintf("%s?error=%s", loginPath, url.QueryEscape(desc))
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	// Read and verify SSO state from cookie
	ssoData, err := h.ssoSession.Get(r)
	if err != nil {
		http.Error(w, "Invalid or expired SSO session", http.StatusBadRequest)
		return
	}

	// Clear SSO cookie immediately (regardless of state match outcome)
	h.ssoSession.Clear(w)

	// Verify state matches (prevents CSRF)
	if ssoData.UserID != state {
		http.Error(w, "State mismatch — possible CSRF attack", http.StatusBadRequest)
		return
	}

	providerID := ssoData.ProviderID
	returnTo := ssoData.Email // We stored return_to in the Email field

	// Re-validate return_to from cookie (defense in depth)
	if !isValidSSOReturnTo(returnTo) || returnTo == "" {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}

	// Look up the identity provider
	provider, err := h.idpRegistry.Get(providerID)
	if err != nil {
		http.Error(w, "Unknown identity provider", http.StatusInternalServerError)
		return
	}

	// Exchange code for access token
	token, err := provider.Exchange(ctx, code)
	if err != nil {
		log.Printf("sso: exchange code: %v", err)
		redirectWithError(w, r, returnTo, "Authentication failed. Please try again.")
		return
	}

	// Fetch user info from identity provider
	userInfo, err := provider.GetUserInfo(ctx, token)
	if err != nil {
		log.Printf("sso: get userinfo: %v", err)
		redirectWithError(w, r, returnTo, "Could not retrieve your identity. Please try again.")
		return
	}

	// Look up or auto-provision user
	user, err := h.store.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			log.Printf("sso: store error: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		// Auto-provision: create new user
		role := "user"
		for _, adminEmail := range h.bootstrapAdmins {
			if strings.EqualFold(adminEmail, userInfo.Email) {
				role = "admin"
				break
			}
		}

		user = &store.User{
			ID:    uuid.NewString(),
			Email: userInfo.Email,
			Name:  userInfo.Name,
			Role:  role,
		}
		if user.Name == "" {
			user.Name = userInfo.Email
		}
		if err := h.store.CreateUser(ctx, user); err != nil {
			log.Printf("sso: create user: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("sso: auto-provisioned user %s (role=%s)", userInfo.Email, role)
	}

	// Determine which session to create based on return_to path
	if strings.HasPrefix(returnTo, "/admin/") {
		// Admin login — verify admin role
		if user.Role != "admin" {
			redirectWithError(w, r, returnTo, "Access denied. Admin privileges required.")
			return
		}
		if err := h.adminSession.Create(w, &auth.SessionData{
			UserID:     user.ID,
			Email:      user.Email,
			Role:       user.Role,
			ProviderID: user.ProviderID,
		}); err != nil {
			log.Printf("sso: create admin session: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	} else if strings.HasPrefix(returnTo, "/oauth/") {
		// OAuth login — create OAuth session
		if err := h.oauthSession.Create(w, &auth.SessionData{
			UserID:     user.ID,
			Email:      user.Email,
			Role:       user.Role,
			ProviderID: user.ProviderID,
		}); err != nil {
			log.Printf("sso: create oauth session: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}

	// Update last login time
	if err := h.store.UpdateLastLogin(ctx, user.ID); err != nil {
		log.Printf("sso: update last login: %v", err)
	}

	// Redirect to the original destination
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// isValidSSOReturnTo validates that the return URL is a safe relative path.
func isValidSSOReturnTo(u string) bool {
	if u == "" {
		return true
	}
	return strings.HasPrefix(u, "/oauth/") || strings.HasPrefix(u, "/admin/")
}

// redirectWithError redirects to the login page with an error message.
func redirectWithError(w http.ResponseWriter, r *http.Request, returnTo, errMsg string) {
	loginPath := "/oauth/login"
	if strings.HasPrefix(returnTo, "/admin/") {
		loginPath = "/admin/login"
	}
	target := fmt.Sprintf("%s?return_to=%s&error=%s", loginPath, url.QueryEscape(returnTo), url.QueryEscape(errMsg))
	http.Redirect(w, r, target, http.StatusFound)
}
