package handler

import (
	"net/http"

	"github.com/ory/fosite"

	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/store"
)

// OAuthHandler handles OAuth 2.1 AS endpoints (PKCE authorization code flow).
type OAuthHandler struct {
	oauth *auth.OAuth21Server
	jwt   *auth.JWTService
	store store.Store
}

func NewOAuthHandler(oauth *auth.OAuth21Server, jwt *auth.JWTService, st store.Store) *OAuthHandler {
	return &OAuthHandler{oauth: oauth, jwt: jwt, store: st}
}

// HandleAuthorize handles GET /oauth/authorize — PKCE authorization endpoint.
func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ar, err := h.oauth.Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.oauth.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Grant requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	session := newFositeSession("")
	resp, err := h.oauth.Provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		h.oauth.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	h.oauth.Provider.WriteAuthorizeResponse(ctx, w, ar, resp)
}

// HandleToken handles POST /oauth/token — code exchange, refresh.
func (h *OAuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := newFositeSession("")
	ar, err := h.oauth.Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.oauth.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Grant requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	resp, err := h.oauth.Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		h.oauth.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	h.oauth.Provider.WriteAccessResponse(ctx, w, ar, resp)
}

// HandleRevoke handles POST /oauth/revoke — token revocation.
func (h *OAuthHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.oauth.Provider.NewRevocationRequest(ctx, r)
	h.oauth.Provider.WriteRevocationResponse(ctx, w, err)
}

func newFositeSession(subject string) *fosite.DefaultSession {
	return &fosite.DefaultSession{
		Subject: subject,
	}
}
