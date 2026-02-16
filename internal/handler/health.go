package handler

import (
	"encoding/json"
	"net/http"

	"github.com/piper/oauth-token-relay/internal/provider"
)

type HealthHandler struct {
	registry *provider.Registry
}

func NewHealthHandler(registry *provider.Registry) *HealthHandler {
	return &HealthHandler{registry: registry}
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"providers": h.registry.List(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
