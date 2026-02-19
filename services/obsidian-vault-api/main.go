package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	VaultRoot       string
	Addr            string
	JWTIssuer       string
	JWTAudience     string
	JWTSecret       []byte // HS256 secret
	SearchTimeout   time.Duration
	MaxSearchHits   int
	MaxFileBytes    int64
	AllowListPrefix []string // optional: restrict reads to specific folders (relative)
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing env var %s", key)
	}
	return v
}

func getEnv(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func main() {
	cfg := Config{
		VaultRoot:     mustEnv("OBSIDIAN_VAULT_ROOT"), // absolute path to vault root
		Addr:          getEnv("ADDR", ":8787"),
		JWTIssuer:     getEnv("JWT_ISSUER", "obsidian-vault-api"),
		JWTAudience:   getEnv("JWT_AUDIENCE", "vault-clients"),
		JWTSecret:     []byte(mustEnv("JWT_SECRET")), // long random string
		SearchTimeout: 3 * time.Second,
		MaxSearchHits: 50,
		MaxFileBytes:  2 << 20, // 2 MiB per file read
		// AllowListPrefix: []string{"World", "Sessions"}, // optional
	}

	// Normalize vault root
	absRoot, err := filepath.Abs(cfg.VaultRoot)
	if err != nil {
		log.Fatalf("bad vault root: %v", err)
	}
	cfg.VaultRoot = filepath.Clean(absRoot)

	r := setupRouter(cfg)

	log.Printf("Vault API listening on %s (root=%s)", cfg.Addr, cfg.VaultRoot)
	if err := http.ListenAndServe(cfg.Addr, r); err != nil {
		log.Fatal(err)
	}
}
