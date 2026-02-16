package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig              `yaml:"server"`
	Storage   StorageConfig             `yaml:"storage"`
	Backup    BackupConfig              `yaml:"backup"`
	JWT       JWTConfig                 `yaml:"jwt"`
	Providers map[string]ProviderConfig `yaml:"providers"`
	Admin     AdminConfig               `yaml:"admin"`
}

type ServerConfig struct {
	Address         string        `yaml:"address"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type StorageConfig struct {
	Driver   string         `yaml:"driver"`
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type SQLiteConfig struct {
	Path string `yaml:"path"`
}

type PostgresConfig struct {
	DSN string `yaml:"dsn"`
}

type BackupConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Bucket   string        `yaml:"bucket"`
	Prefix   string        `yaml:"prefix"`
	Interval time.Duration `yaml:"interval"`
	Region   string        `yaml:"region"`
}

type JWTConfig struct {
	SigningKey       string        `yaml:"signing_key"`
	Issuer          string        `yaml:"issuer"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
}

type ProviderConfig struct {
	DisplayName  string            `yaml:"display_name"`
	ClientID     string            `yaml:"client_id"`
	ClientSecret string            `yaml:"client_secret"`
	AuthorizeURL string            `yaml:"authorize_url"`
	TokenURL     string            `yaml:"token_url"`
	RevokeURL    string            `yaml:"revoke_url"`
	ExtraParams  map[string]string `yaml:"extra_params"`
}

type AdminConfig struct {
	BootstrapAdmins []string `yaml:"bootstrap_admins"`
}

// Load reads a YAML config file, expands environment variables, and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Address == "" {
		c.Server.Address = ":8080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 30 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 30 * time.Second
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.JWT.AccessTokenTTL == 0 {
		c.JWT.AccessTokenTTL = 1 * time.Hour
	}
	if c.JWT.RefreshTokenTTL == 0 {
		c.JWT.RefreshTokenTTL = 720 * time.Hour
	}
	if c.Backup.Interval == 0 {
		c.Backup.Interval = 1 * time.Hour
	}
	if c.Backup.Prefix == "" {
		c.Backup.Prefix = "oauth-token-relay/"
	}
}

// Validate checks that required fields are present and values are sane.
func (c *Config) Validate() error {
	if c.JWT.SigningKey == "" {
		return fmt.Errorf("jwt.signing_key is required")
	}
	if c.Storage.Driver != "sqlite" && c.Storage.Driver != "postgres" {
		return fmt.Errorf("storage.driver must be 'sqlite' or 'postgres', got %q", c.Storage.Driver)
	}
	if c.Storage.Driver == "sqlite" && c.Storage.SQLite.Path == "" {
		return fmt.Errorf("storage.sqlite.path is required when driver is sqlite")
	}
	if c.Storage.Driver == "postgres" && c.Storage.Postgres.DSN == "" {
		return fmt.Errorf("storage.postgres.dsn is required when driver is postgres")
	}
	return nil
}
