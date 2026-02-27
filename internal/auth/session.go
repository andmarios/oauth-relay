package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	defaultCookieName = "_otr_session"
	defaultCookiePath = "/oauth/"
	defaultSessionTTL = 10 * time.Minute
)

// SessionData holds the authenticated user's identity during the OAuth authorize flow.
// The State and ReturnTo fields are used by the SSO state cookie to store the OAuth state
// nonce and return URL during the identity provider redirect.
type SessionData struct {
	UserID     string    `json:"uid"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	ProviderID string    `json:"pid"`
	State      string    `json:"state,omitempty"`
	ReturnTo   string    `json:"return_to,omitempty"`
	ExpiresAt  time.Time `json:"exp"`
}

// SessionManager handles encrypted login sessions via HTTP cookies.
// Sessions are AES-GCM encrypted and short-lived by default (10 minutes).
type SessionManager struct {
	aead       cipher.AEAD
	cookieName string
	path       string
	ttl        time.Duration
	secure     bool // true when served over HTTPS
}

// SessionOption configures a SessionManager.
type SessionOption func(*SessionManager)

// WithCookieName sets a custom cookie name.
func WithCookieName(name string) SessionOption {
	return func(m *SessionManager) { m.cookieName = name }
}

// WithPath sets the cookie path.
func WithPath(path string) SessionOption {
	return func(m *SessionManager) { m.path = path }
}

// WithTTL sets the session duration.
func WithTTL(ttl time.Duration) SessionOption {
	return func(m *SessionManager) { m.ttl = ttl }
}

// NewSessionManager creates a session manager using the given key for AES-GCM encryption.
// The key is SHA-256 hashed to ensure exactly 32 bytes for AES-256.
// Options can override the default cookie name, path, and TTL.
func NewSessionManager(key []byte, secure bool, opts ...SessionOption) (*SessionManager, error) {
	// Derive a 32-byte key via SHA-256
	hash := sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	m := &SessionManager{
		aead:       aead,
		cookieName: defaultCookieName,
		path:       defaultCookiePath,
		ttl:        defaultSessionTTL,
		secure:     secure,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// Create sets an encrypted session cookie on the response.
func (m *SessionManager) Create(w http.ResponseWriter, data *SessionData) error {
	data.ExpiresAt = time.Now().Add(m.ttl)

	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}

	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := m.aead.Seal(nonce, nonce, plaintext, nil)
	encoded := base64.URLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    encoded,
		Path:     m.path,
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.secure,
	})
	return nil
}

// Get reads and decrypts the session cookie. Returns nil if no valid session exists.
func (m *SessionManager) Get(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, errors.New("invalid session encoding")
	}

	nonceSize := m.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid session data")
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := m.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, errors.New("session decryption failed")
	}

	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, errors.New("invalid session payload")
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	return &data, nil
}

// Clear removes the session cookie.
func (m *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.path,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   m.secure,
	})
}
