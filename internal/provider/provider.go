package provider

import "context"

// TokenResult holds tokens returned from a provider exchange or refresh.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// Provider defines the interface for an upstream OAuth 2.0 provider.
type Provider interface {
	ID() string
	DisplayName() string
	AuthURL(state string, scopes []string) string
	Exchange(ctx context.Context, code string) (*TokenResult, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenResult, error)
	Revoke(ctx context.Context, token string) error
}
