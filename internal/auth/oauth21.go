package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/token/hmac"
)

// OAuth21Config configures the OAuth 2.1 authorization server.
type OAuth21Config struct {
	Issuer    string
	SecretKey []byte
	Clients   []*OAuth21Client
}

// OAuth21Client represents a registered OAuth client (e.g., the CLI).
type OAuth21Client struct {
	ID            string
	Secret        string
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	Public        bool
}

// OAuth21Server wraps Fosite to provide OAuth 2.1 AS functionality.
type OAuth21Server struct {
	Provider fosite.OAuth2Provider
	Store    *MemoryStore
}

// NewOAuth21Server creates a configured Fosite-backed OAuth 2.1 server.
func NewOAuth21Server(cfg OAuth21Config) *OAuth21Server {
	store := NewMemoryStore()

	for _, c := range cfg.Clients {
		fc := &fosite.DefaultClient{
			ID:            c.ID,
			RedirectURIs:  c.RedirectURIs,
			GrantTypes:    c.GrantTypes,
			ResponseTypes: c.ResponseTypes,
			Scopes:        c.Scopes,
			Public:        c.Public,
		}
		store.SetClient(c.ID, fc)
	}

	key := cfg.SecretKey
	if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		key = padded
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:         time.Hour,
		RefreshTokenLifespan:        30 * 24 * time.Hour,
		AuthorizeCodeLifespan:       10 * time.Minute,
		EnforcePKCE:                 true,
		EnforcePKCEForPublicClients: true,
		GlobalSecret:                key,
		TokenURL:                    cfg.Issuer + "/oauth/token",
	}

	hmacStrategy := &hmac.HMACStrategy{Config: fositeConfig}
	coreStrategy := fositeOAuth2.NewHMACSHAStrategy(hmacStrategy, fositeConfig)

	provider := compose.Compose(
		fositeConfig,
		store,
		&compose.CommonStrategy{CoreStrategy: coreStrategy},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
	)

	return &OAuth21Server{
		Provider: provider,
		Store:    store,
	}
}

// GenerateState creates a cryptographically random state string.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// --- MemoryStore: Fosite storage adapter ---

// MemoryStore implements Fosite's storage interfaces in-memory.
// Auth codes and Fosite tokens are ephemeral — the server issues its own JWTs after the flow completes.
type MemoryStore struct {
	mu             sync.RWMutex
	clients        map[string]fosite.Client
	authCodes      map[string]fosite.Requester
	accessTokens   map[string]fosite.Requester
	refreshTokens  map[string]storeRefreshToken
	pkceRequests   map[string]fosite.Requester
	invalidCodes   map[string]bool
	jtiKnown       map[string]time.Time
}

type storeRefreshToken struct {
	Request         fosite.Requester
	AccessSignature string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:       make(map[string]fosite.Client),
		authCodes:     make(map[string]fosite.Requester),
		accessTokens:  make(map[string]fosite.Requester),
		refreshTokens: make(map[string]storeRefreshToken),
		pkceRequests:  make(map[string]fosite.Requester),
		invalidCodes:  make(map[string]bool),
		jtiKnown:      make(map[string]time.Time),
	}
}

func (s *MemoryStore) SetClient(id string, client fosite.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = client
}

// --- ClientManager ---

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return c, nil
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if exp, ok := s.jtiKnown[jti]; ok && time.Now().Before(exp) {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jtiKnown[jti] = exp
	now := time.Now()
	for k, v := range s.jtiKnown {
		if now.After(v) {
			delete(s.jtiKnown, k)
		}
	}
	return nil
}

// --- AuthorizeCodeStorage ---

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = req
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.invalidCodes[code] {
		if req, ok := s.authCodes[code]; ok {
			return req, fosite.ErrInvalidatedAuthorizeCode
		}
		return nil, fosite.ErrNotFound
	}
	req, ok := s.authCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidCodes[code] = true
	return nil
}

// --- AccessTokenStorage ---

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[signature] = req
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.accessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, signature)
	return nil
}

// --- RefreshTokenStorage ---

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature string, accessSignature string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[signature] = storeRefreshToken{Request: req, AccessSignature: accessSignature}
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.refreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rt.Request, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, signature)
	return nil
}

func (s *MemoryStore) RevokeRefreshToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.refreshTokens {
		if v.Request.GetID() == requestID {
			delete(s.refreshTokens, k)
			break
		}
	}
	return nil
}

func (s *MemoryStore) RevokeRefreshTokenMaybeGracePeriod(_ context.Context, requestID string, _ string) error {
	return s.RevokeRefreshToken(context.Background(), requestID)
}

func (s *MemoryStore) RevokeAccessToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.accessTokens {
		if v.GetID() == requestID {
			delete(s.accessTokens, k)
			break
		}
	}
	return nil
}

func (s *MemoryStore) RotateRefreshToken(_ context.Context, requestID string, refreshTokenSignature string) error {
	// Rotation: invalidate old refresh token for this request
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.refreshTokens {
		if v.Request.GetID() == requestID && k != refreshTokenSignature {
			delete(s.refreshTokens, k)
		}
	}
	return nil
}

// --- PKCERequestStorage ---

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.pkceRequests[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, signature string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkceRequests[signature] = req
	return nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pkceRequests, signature)
	return nil
}

// Interface compliance checks.
var _ fosite.Storage = (*MemoryStore)(nil)
var _ fositeOAuth2.CoreStorage = (*MemoryStore)(nil)
var _ pkce.PKCERequestStorage = (*MemoryStore)(nil)
