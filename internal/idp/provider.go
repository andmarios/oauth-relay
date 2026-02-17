package idp

import "context"

// UserInfo holds identity information retrieved from an identity provider.
type UserInfo struct {
	Email string
	Name  string
}

// IdentityProvider authenticates users via an external OAuth 2.0 identity provider.
// This is separate from the relay provider package — relay providers issue upstream
// tokens, identity providers verify user identity for login.
type IdentityProvider interface {
	// ID returns the provider's config key (e.g., "google", "github").
	ID() string
	// DisplayName returns a human-friendly name for the login UI.
	DisplayName() string
	// AuthURL builds the authorization redirect URL with the given state nonce.
	AuthURL(state string) string
	// Exchange trades an authorization code for an access token.
	Exchange(ctx context.Context, code string) (token string, err error)
	// GetUserInfo fetches the authenticated user's email and name from the provider.
	GetUserInfo(ctx context.Context, token string) (*UserInfo, error)
}
