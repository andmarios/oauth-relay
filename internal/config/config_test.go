package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	yaml := `
server:
  address: ":9090"
  read_timeout: 10s
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "dGVzdC1rZXktMjU2LWJpdHMtbG9uZy1lbm91Z2g="
  issuer: "test"
  access_token_ttl: 30m
  refresh_token_ttl: 24h
providers:
  test-provider:
    display_name: "Test Provider"
    client_id: "test-id"
    client_secret: "test-secret"
    authorize_url: "https://example.com/auth"
    token_url: "https://example.com/token"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Server.Address != ":9090" {
		t.Errorf("address = %q, want :9090", cfg.Server.Address)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("driver = %q, want sqlite", cfg.Storage.Driver)
	}
	if cfg.JWT.AccessTokenTTL != 30*time.Minute {
		t.Errorf("access_token_ttl = %v, want 30m", cfg.JWT.AccessTokenTTL)
	}
	p, ok := cfg.Providers["test-provider"]
	if !ok {
		t.Fatal("provider test-provider not found")
	}
	if p.DisplayName != "Test Provider" {
		t.Errorf("display_name = %q, want Test Provider", p.DisplayName)
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	t.Setenv("TEST_SECRET", "expanded-secret-that-is-at-least-32-bytes!")
	yaml := `
server:
  address: ":8085"
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "${TEST_SECRET}"
  issuer: "test"
providers: {}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.JWT.SigningKey != "expanded-secret-that-is-at-least-32-bytes!" {
		t.Errorf("signing_key = %q, want expanded value", cfg.JWT.SigningKey)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	yaml := `
storage:
  driver: sqlite
  sqlite:
    path: "./test.db"
jwt:
  signing_key: "key"
  issuer: "test"
providers: {}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Server.Address != ":8085" {
		t.Errorf("default address = %q, want :8080", cfg.Server.Address)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("default read_timeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.SecureCookies == nil || !*cfg.Server.SecureCookies {
		t.Error("default secure_cookies should be true")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateConfig(t *testing.T) {
	base := func() *Config {
		return &Config{
			Storage: StorageConfig{Driver: "sqlite", SQLite: SQLiteConfig{Path: "./test.db"}},
			JWT:     JWTConfig{SigningKey: "test-key-that-is-at-least-32-bytes!!", Issuer: "test"},
			IdentityProviders: map[string]IDPConfig{
				"google": {ClientID: "id", ClientSecret: "secret", AuthorizeURL: "https://a", TokenURL: "https://t", UserInfoURL: "https://u"},
			},
		}
	}

	// Missing signing key
	cfg := base()
	cfg.JWT.SigningKey = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing signing_key")
	}

	// Short signing key (< 32 bytes)
	cfg = base()
	cfg.JWT.SigningKey = "too-short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for short signing_key")
	}

	// Invalid storage driver
	cfg = base()
	cfg.Storage.Driver = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid driver")
	}

	// Provider missing client_id
	cfg = base()
	cfg.Providers = map[string]ProviderConfig{
		"bad": {ClientSecret: "s", AuthorizeURL: "https://a", TokenURL: "https://t"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for provider missing client_id")
	}

	// Valid config
	cfg = base()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}
