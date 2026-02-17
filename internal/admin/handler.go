package admin

import (
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"

	"github.com/piper/oauth-token-relay/internal/admin/ui"
	"github.com/piper/oauth-token-relay/internal/admin/ui/templates"
	"github.com/piper/oauth-token-relay/internal/provider"
	"github.com/piper/oauth-token-relay/internal/store"
)

// UIHandler serves the admin dashboard pages.
type UIHandler struct {
	store    store.Store
	registry *provider.Registry
	mux      *http.ServeMux
}

// NewUIHandler creates the admin UI handler with all routes registered.
func NewUIHandler(st store.Store, reg *provider.Registry) *UIHandler {
	h := &UIHandler{store: st, registry: reg, mux: http.NewServeMux()}

	// Static assets
	staticFS, _ := fs.Sub(ui.Static, "static")
	h.mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(staticFS))))

	// Pages
	h.mux.HandleFunc("GET /admin/", h.handleDashboard)
	h.mux.HandleFunc("GET /admin/users", h.handleUsers)
	h.mux.HandleFunc("GET /admin/users/{id}", h.handleUserDetail)
	h.mux.HandleFunc("GET /admin/audit", h.handleAudit)
	h.mux.HandleFunc("GET /admin/providers", h.handleProviders)

	return h
}

func (h *UIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *UIHandler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, userCount, _ := h.store.ListUsers(ctx, 1, 0)
	stats, _ := h.store.GetUsageStats(ctx, time.Now().AddDate(0, 0, -1))

	data := templates.DashboardData{
		UserCount:  userCount,
		UsageStats: stats,
		Providers:  h.registry.List(),
	}
	templ.Handler(templates.Dashboard(data)).ServeHTTP(w, r)
}

func (h *UIHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r)

	users, total, _ := h.store.ListUsers(r.Context(), limit, offset)
	data := templates.UsersData{
		Users:  users,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	templ.Handler(templates.Users(data)).ServeHTTP(w, r)
}

func (h *UIHandler) handleUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	user, err := h.store.GetUser(ctx, id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	audit, _, _ := h.store.ListAuditEntries(ctx, store.AuditFilter{
		UserID: id,
		Limit:  50,
	})

	data := templates.UserDetailData{
		User:  user,
		Audit: audit,
	}
	templ.Handler(templates.UserDetail(data)).ServeHTTP(w, r)
}

func (h *UIHandler) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r)
	q := r.URL.Query()

	filter := store.AuditFilter{
		UserID: q.Get("user_id"),
		Action: q.Get("action"),
		Limit:  limit,
		Offset: offset,
	}

	entries, total, _ := h.store.ListAuditEntries(r.Context(), filter)
	data := templates.AuditData{
		Entries: entries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		Filter:  filter,
	}
	templ.Handler(templates.Audit(data)).ServeHTTP(w, r)
}

func (h *UIHandler) handleProviders(w http.ResponseWriter, r *http.Request) {
	dbProviders, _ := h.store.ListProviders(r.Context())

	var infos []templates.ProviderInfo
	for _, p := range dbProviders {
		infos = append(infos, templates.ProviderInfo{
			ID:          p.ID,
			DisplayName: p.DisplayName,
		})
	}

	data := templates.ProvidersData{Providers: infos}
	templ.Handler(templates.Providers(data)).ServeHTTP(w, r)
}

func parsePagination(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return
}
