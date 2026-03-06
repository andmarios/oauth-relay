package idp

import (
	"fmt"

	"github.com/piper/oauth-token-relay/internal/config"
)

// Registry maps config IDs to IdentityProvider instances.
type Registry struct {
	providers map[string]IdentityProvider
}

// NewRegistry constructs identity providers from config with the given callback URL.
func NewRegistry(idps map[string]config.IDPConfig, callbackURL string) *Registry {
	r := &Registry{providers: make(map[string]IdentityProvider)}
	for id, cfg := range idps { //nolint:gocritic // map values can't be addressed
		r.providers[id] = NewOAuth2IdentityProvider(&OAuth2IDPConfig{
			ID:           id,
			DisplayName:  cfg.DisplayName,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			AuthorizeURL: cfg.AuthorizeURL,
			TokenURL:     cfg.TokenURL,
			UserInfoURL:  cfg.UserInfoURL,
			Scopes:       cfg.Scopes,
			EmailField:   cfg.EmailField,
			RedirectURL:  callbackURL,
		})
	}
	return r
}

// NewRegistryFromProviders creates a Registry from pre-built IdentityProvider instances.
// This is primarily used for testing with mock providers.
func NewRegistryFromProviders(providers map[string]IdentityProvider) *Registry {
	r := &Registry{providers: make(map[string]IdentityProvider)}
	for id, p := range providers {
		r.providers[id] = p
	}
	return r
}

// Get returns an identity provider by ID.
func (r *Registry) Get(id string) (IdentityProvider, error) {
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("identity provider %q not found", id)
	}
	return p, nil
}

// List returns all registered identity providers (for rendering login buttons).
func (r *Registry) List() []IdentityProvider {
	result := make([]IdentityProvider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
