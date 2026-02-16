package auth

import (
	"testing"
	"time"
)

func newTestJWT() *JWTService {
	return NewJWTService("test-secret-key-256-bits-long!!", "test-issuer", 1*time.Hour, 24*time.Hour)
}

func TestIssueAndValidateAccessToken(t *testing.T) {
	svc := newTestJWT()

	token, err := svc.IssueAccessToken("user-123", "alice@example.com", "admin", "google-corp")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", claims.Subject)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", claims.Email)
	}
	if claims.Role != "admin" {
		t.Errorf("role = %q, want admin", claims.Role)
	}
	if claims.ProviderID != "google-corp" {
		t.Errorf("provider_id = %q, want google-corp", claims.ProviderID)
	}
	if claims.TokenType != "access" {
		t.Errorf("token_type = %q, want access", claims.TokenType)
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("issuer = %q, want test-issuer", claims.Issuer)
	}
}

func TestIssueAndValidateRefreshToken(t *testing.T) {
	svc := newTestJWT()

	token, jti, err := svc.IssueRefreshToken("user-123")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}
	if jti == "" {
		t.Fatal("jti is empty")
	}

	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", claims.Subject)
	}
	if claims.TokenType != "refresh" {
		t.Errorf("token_type = %q, want refresh", claims.TokenType)
	}
	if claims.ID != jti {
		t.Errorf("jti = %q, want %q", claims.ID, jti)
	}
}

func TestExpiredToken(t *testing.T) {
	svc := NewJWTService("test-secret-key-256-bits-long!!", "test-issuer", -1*time.Hour, -1*time.Hour)

	token, err := svc.IssueAccessToken("user-123", "a@b.com", "user", "google")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = svc.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestTamperedToken(t *testing.T) {
	svc := newTestJWT()

	token, err := svc.IssueAccessToken("user-123", "a@b.com", "user", "google")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Tamper with the token
	tampered := token[:len(token)-4] + "XXXX"
	_, err = svc.ValidateToken(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestWrongSigningKey(t *testing.T) {
	svc1 := NewJWTService("key-one-256-bits-long-enough!!!", "issuer", 1*time.Hour, 24*time.Hour)
	svc2 := NewJWTService("key-two-256-bits-long-enough!!!", "issuer", 1*time.Hour, 24*time.Hour)

	token, err := svc1.IssueAccessToken("user-123", "a@b.com", "user", "google")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = svc2.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestInvalidTokenString(t *testing.T) {
	svc := newTestJWT()
	_, err := svc.ValidateToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid token string")
	}
}
