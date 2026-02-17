package auth

import (
	"context"
	"net/http"
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
