package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/piper/oauth-token-relay/internal/httputil"
	"github.com/piper/oauth-token-relay/internal/store"
)

// AdminHandler handles admin API endpoints.
// All endpoints require admin role (enforced by RequireAdmin middleware at routing).
type AdminHandler struct {
	store store.Store
}

func NewAdminHandler(st store.Store) *AdminHandler {
	return &AdminHandler{store: st}
}

// HandleListUsers handles GET /admin/users.
// Query params: limit (default 50), offset (default 0).
func (h *AdminHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := h.store.ListUsers(r.Context(), limit, offset)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// HandleGetUser handles GET /admin/users/{id}.
// Returns user details plus recent audit entries.
func (h *AdminHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user id required"})
		return
	}

	user, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httputil.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		} else {
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	audit, _, _ := h.store.ListAuditEntries(r.Context(), store.AuditFilter{
		UserID: id,
		Limit:  20,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user":  user,
		"audit": audit,
	})
}

// HandleDeleteUser handles DELETE /admin/users/{id}.
// Deletes the user and revokes all their refresh tokens.
func (h *AdminHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user id required"})
		return
	}

	if err := h.store.DeleteUserRefreshTokens(r.Context(), id); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// HandleAssignProvider handles POST /admin/users/{id}/assign-provider.
// Body: { "provider_id": "..." }
func (h *AdminHandler) HandleAssignProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user id required"})
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := httputil.ReadJSON(w, r, &req); err != nil || req.ProviderID == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id required"})
		return
	}

	// Validate provider exists (#3)
	if _, err := h.store.GetProvider(r.Context(), req.ProviderID); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "provider not found"})
		return
	}

	user, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httputil.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		} else {
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	user.ProviderID = req.ProviderID
	if err := h.store.UpdateUser(r.Context(), user); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": user})
}

// HandleUsageStats handles GET /admin/usage.
// Query param: since (RFC3339, default 30 days ago).
func (h *AdminHandler) HandleUsageStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().AddDate(0, 0, -30)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	stats, err := h.store.GetUsageStats(r.Context(), since)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"stats": stats,
		"since": since.Format(time.RFC3339),
	})
}

// HandleAuditLog handles GET /admin/audit.
// Query params: user_id, provider_id, action, since, until, limit, offset.
func (h *AdminHandler) HandleAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	filter := store.AuditFilter{
		UserID:     q.Get("user_id"),
		ProviderID: q.Get("provider_id"),
		Action:     q.Get("action"),
		Limit:      limit,
		Offset:     offset,
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Since = &t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Until = &t
		}
	}

	entries, total, err := h.store.ListAuditEntries(r.Context(), filter)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// HandleListProviders handles GET /admin/providers.
func (h *AdminHandler) HandleListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListProviders(r.Context())
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"providers": providers,
	})
}
