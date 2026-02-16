package provider

import (
	"fmt"

	"github.com/piper/oauth-token-relay/internal/config"
)

// Registry manages configured OAuth providers.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry creates a Registry from provider configuration.
func NewRegistry(providers map[string]config.ProviderConfig, baseURL string) *Registry {
	r := &Registry{providers: make(map[string]Provider)}
	for id, cfg := range providers {
		r.providers[id] = NewOAuth2Provider(OAuth2Config{
			ID:           id,
			DisplayName:  cfg.DisplayName,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			AuthorizeURL: cfg.AuthorizeURL,
			TokenURL:     cfg.TokenURL,
			RevokeURL:    cfg.RevokeURL,
			RedirectURL:  baseURL + "/auth/tokens/callback",
			ExtraParams:  cfg.ExtraParams,
		})
	}
	return r
}

// Get returns a provider by ID.
func (r *Registry) Get(id string) (Provider, error) {
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("provider %q not found", id)
	}
	return p, nil
}

// List returns all registered provider IDs.
func (r *Registry) List() []string {
	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	return ids
}
