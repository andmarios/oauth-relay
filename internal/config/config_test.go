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
    scopes_mapping:
      docs: "https://example.com/scope/docs"
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
	if p.ScopesMapping["docs"] != "https://example.com/scope/docs" {
		t.Errorf("scope docs = %q", p.ScopesMapping["docs"])
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	t.Setenv("TEST_SECRET", "expanded-secret")
	yaml := `
server:
  address: ":8080"
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
	if cfg.JWT.SigningKey != "expanded-secret" {
		t.Errorf("signing_key = %q, want expanded-secret", cfg.JWT.SigningKey)
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
	if cfg.Server.Address != ":8080" {
		t.Errorf("default address = %q, want :8080", cfg.Server.Address)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("default read_timeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateConfig(t *testing.T) {
	// Missing signing key
	cfg := &Config{
		Storage: StorageConfig{Driver: "sqlite", SQLite: SQLiteConfig{Path: "./test.db"}},
		JWT:     JWTConfig{Issuer: "test"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing signing_key")
	}

	// Invalid storage driver
	cfg.JWT.SigningKey = "key"
	cfg.Storage.Driver = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid driver")
	}
}
