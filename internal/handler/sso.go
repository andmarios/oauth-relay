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
		// Always default to /admin/ — never to bare /oauth/authorize which
		// requires PKCE params from a CLI-initiated flow.
		returnTo = "/admin/"
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
		errorHTML = fmt.Sprintf(`<div class="error-msg">%s</div>`, html.EscapeString(errMsg))
	}

	var buttons strings.Builder
	for _, p := range providers {
		name := p.DisplayName()
		nameUpper := strings.ToUpper(name)

		var btnClass, btnIcon string
		switch {
		case strings.Contains(nameUpper, "GOOGLE"):
			btnClass = "sso-btn sso-btn-google"
			btnIcon = `<svg viewBox="0 0 24 24" width="20" height="20"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>`
		case strings.Contains(nameUpper, "GITHUB"):
			btnClass = "sso-btn sso-btn-github"
			btnIcon = `<svg viewBox="0 0 24 24" width="20" height="20" fill="white"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>`
		default:
			btnClass = "sso-btn sso-btn-default"
			btnIcon = `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>`
		}

		buttons.WriteString(fmt.Sprintf(
			`<a href="/sso/start/%s?return_to=%s" class="%s">%s Sign in with %s</a>`,
			html.EscapeString(p.ID()),
			url.QueryEscape(returnTo),
			btnClass,
			btnIcon,
			html.EscapeString(name),
		))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s — OAuth Token Relay</title>
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <link rel="stylesheet" href="/static/login.css">
</head>
<body>
    <div class="card">
        <div class="logo-wrap">
            <img src="/static/logo.png" alt="OAuth Token Relay">
        </div>
        <p class="brand">OAuth Token Relay</p>
        <h1>%s</h1>
        <p class="subtitle">%s</p>
        %s
        <hr class="divider">
        %s
    </div>
    <div class="footer">Secure authentication</div>
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

	// Auto-assign relay provider if user has none and exactly one exists
	if user.ProviderID == "" {
		providers, listErr := h.store.ListProviders(ctx)
		if listErr == nil && len(providers) == 1 {
			user.ProviderID = providers[0].ID
			if updateErr := h.store.UpdateUser(ctx, user); updateErr != nil {
				log.Printf("sso: auto-assign provider: %v", updateErr)
			} else {
				log.Printf("sso: auto-assigned provider %s to user %s", providers[0].ID, user.Email)
			}
		}
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
