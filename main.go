package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
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

	r := chi.NewRouter()

	// Minimal logging
	r.Use(requestLogMiddleware)

	// Health is public
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Protected routes
	r.Group(func(pr chi.Router) {
		pr.Use(jwtAuthMiddleware(cfg))
		pr.Route("/v1", func(v1 chi.Router) {
			v1.Get("/notes", listNotesHandler(cfg))
			v1.Get("/note", getNoteHandler(cfg))
			v1.Get("/search", searchHandler(cfg))
		})
	})

	log.Printf("Vault API listening on %s (root=%s)", cfg.Addr, cfg.VaultRoot)
	if err := http.ListenAndServe(cfg.Addr, r); err != nil {
		log.Fatal(err)
	}
}

/* -------------------- Middleware -------------------- */

func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func jwtAuthMiddleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			tokenStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))

			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
				// Only allow HS256
				if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return cfg.JWTSecret, nil
			},
				jwt.WithIssuer(cfg.JWTIssuer),
				jwt.WithAudience(cfg.JWTAudience),
				jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
				jwt.WithLeeway(30*time.Second), // clock skew tolerance
			)

			if err != nil || !token.Valid {
				writeErr(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Require exp
			if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) <= 0 {
				writeErr(w, http.StatusUnauthorized, "token expired")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

/* -------------------- Handlers -------------------- */

func listNotesHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimSpace(r.URL.Query().Get("prefix")) // relative folder within vault
		root, err := safeJoin(cfg, prefix)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		notes := make([]string, 0, 256)
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".md" && ext != ".markdown" {
				return nil
			}
			rel, relErr := filepath.Rel(cfg.VaultRoot, path)
			if relErr != nil {
				return relErr
			}
			notes = append(notes, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list notes")
			return
		}

		sort.Strings(notes)
		writeJSON(w, http.StatusOK, map[string]any{"notes": notes, "count": len(notes)})
	}
}

func getNoteHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		relPath := strings.TrimSpace(r.URL.Query().Get("path"))
		if relPath == "" {
			writeErr(w, http.StatusBadRequest, "missing path")
			return
		}

		p, err := safeJoin(cfg, relPath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		// Only allow markdown reads
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".md" && ext != ".markdown" {
			writeErr(w, http.StatusBadRequest, "only markdown files allowed")
			return
		}

		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, "stat failed")
			return
		}
		if fi.Size() > cfg.MaxFileBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
			return
		}

		b, err := os.ReadFile(p)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "read failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"path":    filepath.ToSlash(relPath),
			"content": string(b),
		})
	}
}

type SearchHit struct {
	Path    string `json:"path"`
	Snippet string `json:"snippet"`
}

func searchHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			writeErr(w, http.StatusBadRequest, "missing q")
			return
		}

		limit := cfg.MaxSearchHits
		if s := strings.TrimSpace(r.URL.Query().Get("limit")); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), cfg.SearchTimeout)
		defer cancel()

		// Prefer ripgrep if available
		hits, err := searchWithRipgrep(ctx, cfg, q, limit)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"q": q, "hits": hits, "count": len(hits), "engine": "ripgrep"})
			return
		}

		// Fallback: naive scan
		hits, err = searchNaive(ctx, cfg, q, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "search failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"q": q, "hits": hits, "count": len(hits), "engine": "naive"})
	}
}

/* -------------------- Search engines -------------------- */

// ripgrep output: "path:line:match"
func searchWithRipgrep(ctx context.Context, cfg Config, q string, limit int) ([]SearchHit, error) {
	_, lookErr := exec.LookPath("rg")
	if lookErr != nil {
		return nil, lookErr
	}

	// -n line numbers, --no-heading, --color never
	// --max-count limits matches per file; we also cap total hits manually
	cmd := exec.CommandContext(ctx, "rg",
		"-n", "--no-heading", "--color", "never",
		"--max-count", "3",
		q, cfg.VaultRoot,
	)
	out, err := cmd.Output()
	if err != nil {
		// rg returns exit code 1 for "no matches" — treat as empty success
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return []SearchHit{}, nil
		}
		return nil, err
	}

	hits := make([]SearchHit, 0, min(limit, 50))
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		// split path:line:content (only first 2 colons)
		p1 := strings.IndexByte(line, ':')
		if p1 <= 0 {
			continue
		}
		p2 := strings.IndexByte(line[p1+1:], ':')
		if p2 <= 0 {
			continue
		}
		p2 = p1 + 1 + p2

		path := line[:p1]
		content := strings.TrimSpace(line[p2+1:])

		rel, err := filepath.Rel(cfg.VaultRoot, path)
		if err != nil {
			continue
		}
		hits = append(hits, SearchHit{
			Path:    filepath.ToSlash(rel),
			Snippet: truncate(content, 240),
		})
		if len(hits) >= limit {
			break
		}
	}
	return hits, sc.Err()
}

func searchNaive(ctx context.Context, cfg Config, q string, limit int) ([]SearchHit, error) {
	qLower := strings.ToLower(q)
	hits := make([]SearchHit, 0, min(limit, 50))

	err := filepath.WalkDir(cfg.VaultRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".md" && ext != ".markdown" {
			return nil
		}

		fi, err := os.Stat(path)
		if err != nil || fi.Size() > cfg.MaxFileBytes {
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(b)
		idx := strings.Index(strings.ToLower(text), qLower)
		if idx < 0 {
			return nil
		}

		rel, err := filepath.Rel(cfg.VaultRoot, path)
		if err != nil {
			return nil
		}

		start := max(0, idx-120)
		end := min(len(text), idx+120)
		snippet := strings.ReplaceAll(text[start:end], "\n", " ")
		hits = append(hits, SearchHit{Path: filepath.ToSlash(rel), Snippet: truncate(strings.TrimSpace(snippet), 240)})

		if len(hits) >= limit {
			return fs.SkipAll
		}
		return nil
	})

	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, err
	}
	return hits, nil
}

/* -------------------- Safety + helpers -------------------- */

func safeJoin(cfg Config, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	rel = strings.TrimPrefix(rel, "/")
	rel = strings.ReplaceAll(rel, "\\", "/")

	if strings.Contains(rel, "\x00") {
		return "", errors.New("invalid path")
	}

	// Optional allowlist (e.g. only allow reads from World/, Sessions/)
	if len(cfg.AllowListPrefix) > 0 && rel != "" {
		ok := false
		for _, p := range cfg.AllowListPrefix {
			p = strings.TrimSuffix(filepath.ToSlash(p), "/")
			if rel == p || strings.HasPrefix(rel, p+"/") {
				ok = true
				break
			}
		}
		if !ok {
			return "", errors.New("path not allowed")
		}
	}

	joined := filepath.Join(cfg.VaultRoot, filepath.FromSlash(rel))
	clean := filepath.Clean(joined)

	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", errors.New("bad path")
	}

	// Must remain within cfg.VaultRoot
	rootWithSep := cfg.VaultRoot + string(os.PathSeparator)
	if abs != cfg.VaultRoot && !strings.HasPrefix(abs, rootWithSep) {
		return "", errors.New("path escapes vault")
	}
	return abs, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
