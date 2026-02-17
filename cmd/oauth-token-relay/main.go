package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/piper/oauth-token-relay/internal/admin"
	"github.com/piper/oauth-token-relay/internal/auth"
	"github.com/piper/oauth-token-relay/internal/config"
	"github.com/piper/oauth-token-relay/internal/handler"
	"github.com/piper/oauth-token-relay/internal/idp"
	"github.com/piper/oauth-token-relay/internal/provider"
	"github.com/piper/oauth-token-relay/internal/server"
	"github.com/piper/oauth-token-relay/internal/store"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("validate config: %v", err)
	}

	// Initialize store
	var st store.Store
	switch cfg.Storage.Driver {
	case "sqlite":
		sqliteStore, err := store.NewSQLiteStore(cfg.Storage.SQLite.Path)
		if err != nil {
			log.Fatalf("open sqlite: %v", err)
		}
		defer sqliteStore.Close()
		st = sqliteStore

		// Start S3 backup if enabled
		if cfg.Backup.Enabled {
			startBackup(sqliteStore, cfg.Backup)
		}
	case "postgres":
		log.Fatal("PostgreSQL driver not yet implemented")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Sync providers from config → DB
	syncProviders(ctx, st, cfg.Providers)

	// Bootstrap admin users
	bootstrapAdmins(ctx, st, cfg.Admin.BootstrapAdmins)

	// Initialize services
	jwtSvc := auth.NewJWTService(
		cfg.JWT.SigningKey,
		cfg.JWT.Issuer,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
	)

	baseURL := "http://localhost" + cfg.Server.Address
	registry := provider.NewRegistry(cfg.Providers, baseURL)
	idpRegistry := idp.NewRegistry(cfg.IdentityProviders, baseURL+"/sso/callback")

	oauthServer := auth.NewOAuth21Server(auth.OAuth21Config{
		Issuer:    cfg.JWT.Issuer,
		SecretKey: []byte(cfg.JWT.SigningKey),
		Clients: []*auth.OAuth21Client{{
			ID:            "cli",
			RedirectURIs:  []string{"http://localhost:8085/callback"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "offline"},
			Public:        true,
		}},
	})

	// Session manager for login cookies (uses JWT signing key as encryption key)
	sessionMgr, err := auth.NewSessionManager([]byte(cfg.JWT.SigningKey), false)
	if err != nil {
		log.Fatalf("session manager: %v", err)
	}

	// Session manager for admin browser sessions (longer TTL, scoped to /admin/)
	adminSessionMgr, err := auth.NewSessionManager([]byte(cfg.JWT.SigningKey), false,
		auth.WithCookieName("_otr_admin"),
		auth.WithPath("/admin/"),
		auth.WithTTL(8*time.Hour),
	)
	if err != nil {
		log.Fatalf("admin session manager: %v", err)
	}

	// Session manager for SSO state cookie (stores state nonce during OAuth redirect)
	ssoSessionMgr, err := auth.NewSessionManager([]byte(cfg.JWT.SigningKey), false,
		auth.WithCookieName("_otr_sso"),
		auth.WithPath("/"),
		auth.WithTTL(10*time.Minute),
	)
	if err != nil {
		log.Fatalf("sso session manager: %v", err)
	}

	// Build handlers
	healthH := handler.NewHealthHandler(registry)
	ssoH := handler.NewSSOHandler(st, sessionMgr, adminSessionMgr, ssoSessionMgr, idpRegistry, cfg.Admin.BootstrapAdmins)
	oauthH := handler.NewOAuthHandler(oauthServer, jwtSvc, st, sessionMgr, cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL)
	relayH := handler.NewRelayHandler(st, registry)
	adminAPIH := handler.NewAdminHandler(st)
	adminUIH := admin.NewUIHandler(st, registry)

	// Wire routes
	mux := http.NewServeMux()

	// Health (no auth)
	mux.Handle("GET /health", healthH)

	// SSO login (replaces email-only login — users authenticate via identity provider)
	mux.HandleFunc("GET /oauth/login", ssoH.HandleLoginPage)
	mux.HandleFunc("GET /admin/login", ssoH.HandleLoginPage)
	mux.HandleFunc("GET /sso/start/{provider}", ssoH.HandleSSOStart)
	mux.HandleFunc("GET /sso/callback", ssoH.HandleSSOCallback)

	// OAuth 2.1 AS endpoints (no server auth — these are the auth endpoints)
	mux.HandleFunc("GET /oauth/authorize", oauthH.HandleAuthorize)
	mux.HandleFunc("POST /oauth/token", oauthH.HandleToken)
	mux.HandleFunc("POST /oauth/revoke", oauthH.HandleRevoke)

	// Token relay (requires auth)
	authMW := auth.RequireAuth(jwtSvc)
	mux.Handle("POST /auth/tokens/start", authMW(http.HandlerFunc(relayH.HandleStart)))
	mux.HandleFunc("GET /auth/tokens/callback", relayH.HandleCallback) // Browser redirect, no JWT
	mux.Handle("POST /auth/tokens/complete", authMW(http.HandlerFunc(relayH.HandleComplete)))
	mux.Handle("POST /auth/tokens/refresh", authMW(http.HandlerFunc(relayH.HandleRefresh)))
	mux.Handle("POST /auth/tokens/revoke", authMW(http.HandlerFunc(relayH.HandleRevoke)))

	// Admin API (requires admin — Bearer-only for CLI clients)
	adminMW := auth.RequireAdmin(jwtSvc)
	mux.Handle("GET /admin/api/users", adminMW(http.HandlerFunc(adminAPIH.HandleListUsers)))
	mux.Handle("GET /admin/api/users/{id}", adminMW(http.HandlerFunc(adminAPIH.HandleGetUser)))
	mux.Handle("DELETE /admin/api/users/{id}", adminMW(http.HandlerFunc(adminAPIH.HandleDeleteUser)))
	mux.Handle("POST /admin/api/users/{id}/assign-provider", adminMW(http.HandlerFunc(adminAPIH.HandleAssignProvider)))
	mux.Handle("GET /admin/api/usage", adminMW(http.HandlerFunc(adminAPIH.HandleUsageStats)))
	mux.Handle("GET /admin/api/audit", adminMW(http.HandlerFunc(adminAPIH.HandleAuditLog)))
	mux.Handle("GET /admin/api/providers", adminMW(http.HandlerFunc(adminAPIH.HandleListProviders)))

	// Admin UI (served at /admin/ — accepts Bearer JWT or admin session cookie)
	adminUIMW := auth.RequireAdminUI(jwtSvc, adminSessionMgr)
	mux.Handle("/admin/", adminUIMW(adminUIH))

	// Start token cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				relayH.CleanExpiredTokenCache()
			}
		}
	}()

	// Start server
	srv := server.New(server.Config{
		Address:         cfg.Server.Address,
		ReadTimeout:     cfg.Server.ReadTimeout,
		WriteTimeout:    cfg.Server.WriteTimeout,
		ShutdownTimeout: cfg.Server.ShutdownTimeout,
	}, mux)

	log.Printf("oauth-token-relay starting on %s", cfg.Server.Address)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func bootstrapAdmins(ctx context.Context, st store.Store, emails []string) {
	for _, email := range emails {
		_, err := st.GetUserByEmail(ctx, email)
		if err != nil {
			// Create admin user
			if err := st.CreateUser(ctx, &store.User{
				ID:    uuid.NewString(),
				Email: email,
				Name:  email,
				Role:  "admin",
			}); err != nil {
				log.Printf("bootstrap admin %s: %v", email, err)
			} else {
				log.Printf("bootstrapped admin user: %s", email)
			}
		}
	}
}

func syncProviders(ctx context.Context, st store.Store, providers map[string]config.ProviderConfig) {
	for id, p := range providers {
		cfgJSON, _ := json.Marshal(map[string]any{
			"authorize_url": p.AuthorizeURL,
			"token_url":     p.TokenURL,
			"revoke_url":    p.RevokeURL,
		})
		if err := st.UpsertProvider(ctx, &store.Provider{
			ID:          id,
			DisplayName: p.DisplayName,
			Config:      cfgJSON,
		}); err != nil {
			log.Printf("sync provider %s: %v", id, err)
		} else {
			log.Printf("synced provider: %s (%s)", id, p.DisplayName)
		}
	}
}

func startBackup(sqliteStore *store.SQLiteStore, cfg config.BackupConfig) {
	// S3 backup requires an S3Client implementation (e.g., github.com/aws/aws-sdk-go-v2).
	// BackupManager is fully implemented in internal/store/backup.go but needs an S3Client to wire.
	log.Printf("S3 backup configured but S3 client not yet wired: bucket=%s prefix=%s interval=%s", cfg.Bucket, cfg.Prefix, cfg.Interval)
	_ = sqliteStore
}
