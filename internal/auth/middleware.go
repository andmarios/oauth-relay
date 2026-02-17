package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/piper/oauth-token-relay/internal/httputil"
)

type contextKey string

const claimsKey contextKey = "claims"

// ClaimsFromContext retrieves JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey).(*Claims)
	return claims
}

// RequireAuth returns middleware that validates a Bearer JWT and injects claims into context.
func RequireAuth(jwt *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid authorization header"})
				return
			}

			claims, err := jwt.ValidateToken(token)
			if err != nil {
				httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin returns middleware that validates a Bearer JWT and checks for admin role.
func RequireAdmin(jwt *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// First run RequireAuth, then check role
		return RequireAuth(jwt)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil || claims.Role != "admin" {
				httputil.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequireAdminUI returns middleware for browser-accessible admin pages.
// It accepts either a Bearer JWT (for API clients) or an admin session cookie (for browsers).
// If neither is present, it redirects to the admin login page.
func RequireAdminUI(jwt *JWTService, adminSession *SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try Bearer token first (API clients)
			if token := extractBearerToken(r); token != "" {
				claims, err := jwt.ValidateToken(token)
				if err == nil && claims.Role == "admin" {
					ctx := context.WithValue(r.Context(), claimsKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try admin session cookie (browsers)
			sessionData, err := adminSession.Get(r)
			if err == nil && sessionData.Role == "admin" {
				claims := &Claims{
					Email:      sessionData.Email,
					Role:       sessionData.Role,
					ProviderID: sessionData.ProviderID,
				}
				claims.Subject = sessionData.UserID
				ctx := context.WithValue(r.Context(), claimsKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No valid auth — redirect to admin login
			http.Redirect(w, r, "/admin/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}
