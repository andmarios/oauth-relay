package handler

import (
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/store"
)

// LoginHandler handles user authentication for the OAuth authorize flow.
type LoginHandler struct {
	store   store.Store
	session *auth.SessionManager
}

// NewLoginHandler creates a new login handler.
func NewLoginHandler(st store.Store, session *auth.SessionManager) *LoginHandler {
	return &LoginHandler{store: st, session: session}
}

// HandleLoginPage renders GET /oauth/login — a simple email login form.
func (h *LoginHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if !isValidReturnTo(returnTo) {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}
	renderLoginForm(w, returnTo, "")
}

// HandleLoginSubmit handles POST /oauth/login — validates email and creates session.
func (h *LoginHandler) HandleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.PostFormValue("email"))
	returnTo := r.PostFormValue("return_to")

	// Validate return_to to prevent open redirect
	if !isValidReturnTo(returnTo) {
		http.Error(w, "Invalid return URL", http.StatusBadRequest)
		return
	}

	if email == "" {
		renderLoginForm(w, returnTo, "Email is required.")
		return
	}

	// Look up user
	user, err := h.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			renderLoginForm(w, returnTo, "Email not recognized. Contact your administrator.")
			return
		}
		log.Printf("login: store error: %v", err)
		renderLoginForm(w, returnTo, "An internal error occurred. Please try again.")
		return
	}

	// Create login session
	if err := h.session.Create(w, &auth.SessionData{
		UserID:     user.ID,
		Email:      user.Email,
		Role:       user.Role,
		ProviderID: user.ProviderID,
	}); err != nil {
		log.Printf("login: session create: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Update last login time
	if err := h.store.UpdateLastLogin(ctx, user.ID); err != nil {
		log.Printf("login: update last login: %v", err)
	}

	// Redirect back to authorize
	if returnTo == "" {
		returnTo = "/oauth/authorize"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// isValidReturnTo checks that the return URL is a safe relative path.
func isValidReturnTo(u string) bool {
	if u == "" {
		return true
	}
	// Must be a relative path starting with /oauth/
	return strings.HasPrefix(u, "/oauth/")
}

func renderLoginForm(w http.ResponseWriter, returnTo, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	errorHTML := ""
	if errMsg != "" {
		errorHTML = fmt.Sprintf(`<div style="color:#dc3545;background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;padding:10px 15px;margin-bottom:20px">%s</div>`, html.EscapeString(errMsg))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In — OAuth Token Relay</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 40px; width: 100%%; max-width: 400px; }
        h1 { font-size: 24px; margin-bottom: 8px; color: #333; }
        p.subtitle { color: #666; margin-bottom: 24px; font-size: 14px; }
        label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; color: #333; }
        input[type="email"] { width: 100%%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; margin-bottom: 20px; }
        input[type="email"]:focus { outline: none; border-color: #0066cc; box-shadow: 0 0 0 2px rgba(0,102,204,0.2); }
        button { width: 100%%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0052a3; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Sign In</h1>
        <p class="subtitle">Enter your email to authorize the CLI</p>
        %s
        <form method="POST" action="/oauth/login">
            <input type="hidden" name="return_to" value="%s">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email" required autofocus placeholder="you@company.com">
            <button type="submit">Continue</button>
        </form>
    </div>
</body>
</html>`, errorHTML, html.EscapeString(returnTo))
}
