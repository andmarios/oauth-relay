package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// OAuth2IdentityProvider implements IdentityProvider using generic OAuth2.
type OAuth2IdentityProvider struct {
	id          string
	displayName string
	config      *oauth2.Config
	userinfoURL string
	emailField  string
}

// OAuth2IDPConfig holds configuration for building an OAuth2IdentityProvider.
type OAuth2IDPConfig struct {
	ID           string
	DisplayName  string
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	EmailField   string
	RedirectURL  string
}

// NewOAuth2IdentityProvider creates an OAuth2IdentityProvider from the given config.
func NewOAuth2IdentityProvider(cfg OAuth2IDPConfig) *OAuth2IdentityProvider {
	return &OAuth2IdentityProvider{
		id:          cfg.ID,
		displayName: cfg.DisplayName,
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthorizeURL,
				TokenURL: cfg.TokenURL,
			},
			Scopes:      cfg.Scopes,
			RedirectURL: cfg.RedirectURL,
		},
		userinfoURL: cfg.UserInfoURL,
		emailField:  cfg.EmailField,
	}
}

func (p *OAuth2IdentityProvider) ID() string          { return p.id }
func (p *OAuth2IdentityProvider) DisplayName() string { return p.displayName }

func (p *OAuth2IdentityProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *OAuth2IdentityProvider) Exchange(ctx context.Context, code string) (string, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("idp exchange: %w", err)
	}
	return token.AccessToken, nil
}

// GetUserInfo fetches user identity from the provider's userinfo endpoint.
// For GitHub, the /user/emails endpoint returns an array — we find the primary verified email.
// For other providers, the endpoint returns an object with the email at emailField key.
func (p *OAuth2IdentityProvider) GetUserInfo(ctx context.Context, token string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// GitHub API requires Accept header
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read userinfo: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Truncate body in error message to avoid leaking large responses into logs
		snippet := body
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, fmt.Errorf("userinfo returned status %d: %s", resp.StatusCode, snippet)
	}

	// Try parsing as array first (GitHub /user/emails format)
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err == nil && len(emails) > 0 {
		return parseGitHubEmails(emails)
	}

	// Parse as object (standard OIDC userinfo)
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}

	emailField := p.emailField
	if emailField == "" {
		emailField = "email"
	}

	email, _ := data[emailField].(string)
	if email == "" {
		return nil, fmt.Errorf("email field %q not found in userinfo response", emailField)
	}

	name, _ := data["name"].(string)

	return &UserInfo{Email: email, Name: name}, nil
}

// githubEmail represents a single email from GitHub's /user/emails endpoint.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func parseGitHubEmails(emails []githubEmail) (*UserInfo, error) {
	// Find primary + verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return &UserInfo{Email: e.Email}, nil
		}
	}
	// Fallback: any verified email
	for _, e := range emails {
		if e.Verified {
			return &UserInfo{Email: e.Email}, nil
		}
	}
	return nil, fmt.Errorf("no verified email found in GitHub response")
}
