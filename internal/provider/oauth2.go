package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// OAuth2Provider implements Provider using golang.org/x/oauth2.
type OAuth2Provider struct {
	id          string
	displayName string
	config      *oauth2.Config
	revokeURL   string
	extraParams map[string]string
}

// OAuth2Config holds the configuration for creating an OAuth2Provider.
type OAuth2Config struct {
	ID           string
	DisplayName  string
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	TokenURL     string
	RevokeURL    string
	RedirectURL  string
	ExtraParams  map[string]string
}

// NewOAuth2Provider creates a new generic OAuth 2.0 provider.
func NewOAuth2Provider(cfg OAuth2Config) *OAuth2Provider {
	return &OAuth2Provider{
		id:          cfg.ID,
		displayName: cfg.DisplayName,
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthorizeURL,
				TokenURL: cfg.TokenURL,
			},
			RedirectURL: cfg.RedirectURL,
		},
		revokeURL:   cfg.RevokeURL,
		extraParams: cfg.ExtraParams,
	}
}

func (p *OAuth2Provider) ID() string          { return p.id }
func (p *OAuth2Provider) DisplayName() string { return p.displayName }

// AuthURL builds the authorization URL with the given state and scopes.
func (p *OAuth2Provider) AuthURL(state string, scopes []string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")),
	}
	for k, v := range p.extraParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return p.config.AuthCodeURL(state, opts...)
}

// Exchange trades an authorization code for tokens.
func (p *OAuth2Provider) Exchange(ctx context.Context, code string) (*TokenResult, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	return tokenResultFromOAuth2(token), nil
}

// Refresh uses a refresh token to obtain a new access token.
func (p *OAuth2Provider) Refresh(ctx context.Context, refreshToken string) (*TokenResult, error) {
	src := p.config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	token, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	return tokenResultFromOAuth2(token), nil
}

// Revoke revokes a token at the provider's revocation endpoint.
func (p *OAuth2Provider) Revoke(ctx context.Context, token string) error {
	if p.revokeURL == "" {
		return fmt.Errorf("provider %q does not support token revocation", p.id)
	}

	data := url.Values{
		"token":         {token},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("revoke failed with status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func tokenResultFromOAuth2(t *oauth2.Token) *TokenResult {
	result := &TokenResult{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
	if !t.Expiry.IsZero() {
		secs := int(time.Until(t.Expiry).Seconds())
		if secs < 0 {
			secs = 0
		}
		result.ExpiresIn = secs
	}
	if scope, ok := t.Extra("scope").(string); ok && scope != "" {
		result.Scopes = strings.Split(scope, " ")
	}
	return result
}
