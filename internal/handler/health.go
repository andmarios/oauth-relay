package handler

import (
	"net/http"

	"github.com/piper/oauth-token-relay/internal/httputil"
	"github.com/piper/oauth-token-relay/internal/provider"
)

type HealthHandler struct {
	registry *provider.Registry
}

func NewHealthHandler(registry *provider.Registry) *HealthHandler {
	return &HealthHandler{registry: registry}
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"providers": h.registry.List(),
	})
}
