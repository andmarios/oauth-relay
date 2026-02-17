package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionManagerRoundTrip(t *testing.T) {
	mgr, err := NewSessionManager([]byte("test-key-for-session-encryption!"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	data := &SessionData{
		UserID:     "user-123",
		Email:      "test@example.com",
		Role:       "admin",
		ProviderID: "google-corp",
	}

	// Create session
	w := httptest.NewRecorder()
	if err := mgr.Create(w, data); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Read session back
	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	got, err := mgr.Get(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.UserID != data.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, data.UserID)
	}
	if got.Email != data.Email {
		t.Errorf("Email = %q, want %q", got.Email, data.Email)
	}
	if got.Role != data.Role {
		t.Errorf("Role = %q, want %q", got.Role, data.Role)
	}
	if got.ProviderID != data.ProviderID {
		t.Errorf("ProviderID = %q, want %q", got.ProviderID, data.ProviderID)
	}
}

func TestSessionManagerExpired(t *testing.T) {
	mgr, err := NewSessionManager([]byte("test-key"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	// Set TTL to 0 so session expires immediately
	mgr.ttl = 0

	w := httptest.NewRecorder()
	if err := mgr.Create(w, &SessionData{UserID: "u1"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wait a tiny bit to ensure expiry
	time.Sleep(time.Millisecond)

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	_, err = mgr.Get(req)
	if err == nil {
		t.Error("expected error for expired session")
	}
}

func TestSessionManagerTamperedCookie(t *testing.T) {
	mgr, err := NewSessionManager([]byte("test-key"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  defaultCookieName,
		Value: "dGFtcGVyZWQtZGF0YQ==", // base64 of "tampered-data"
	})

	_, err = mgr.Get(req)
	if err == nil {
		t.Error("expected error for tampered cookie")
	}
}

func TestSessionManagerNoCookie(t *testing.T) {
	mgr, err := NewSessionManager([]byte("test-key"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	_, err = mgr.Get(req)
	if err == nil {
		t.Error("expected error for missing cookie")
	}
}

func TestSessionManagerClear(t *testing.T) {
	mgr, err := NewSessionManager([]byte("test-key"), false)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	w := httptest.NewRecorder()
	mgr.Clear(w)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set (with MaxAge -1)")
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func TestSessionManagerDifferentKeys(t *testing.T) {
	mgr1, _ := NewSessionManager([]byte("key-one"), false)
	mgr2, _ := NewSessionManager([]byte("key-two"), false)

	w := httptest.NewRecorder()
	mgr1.Create(w, &SessionData{UserID: "u1"})

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	_, err := mgr2.Get(req)
	if err == nil {
		t.Error("expected error when decrypting with different key")
	}
}

func TestSessionManagerCookieProperties(t *testing.T) {
	mgr, _ := NewSessionManager([]byte("test-key"), true) // secure=true

	w := httptest.NewRecorder()
	mgr.Create(w, &SessionData{UserID: "u1"})

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie")
	}
	c := cookies[0]
	if c.Name != defaultCookieName {
		t.Errorf("Name = %q, want %q", c.Name, defaultCookieName)
	}
	if c.Path != "/oauth/" {
		t.Errorf("Path = %q, want /oauth/", c.Path)
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly")
	}
	if !c.Secure {
		t.Error("expected Secure when secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}
