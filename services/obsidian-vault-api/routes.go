package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

func setupRouter(cfg Config) http.Handler {
	r := chi.NewRouter()

	// Minimal logging
	r.Use(requestLogMiddleware)

	// Public routes
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	r.Get("/docs", docsHandler())
	r.Get("/openapi.yaml", openapiHandler())

	// Protected routes
	r.Group(func(pr chi.Router) {
		pr.Use(jwtAuthMiddleware(cfg))
		pr.Route("/v1", func(v1 chi.Router) {
			v1.Get("/notes", listNotesHandler(cfg))
			v1.Get("/note", getNoteHandler(cfg))
			v1.Post("/notes/batch", batchGetNotesHandler(cfg))
			v1.Get("/search", searchHandler(cfg))
			v1.Put("/note", putNoteHandler(cfg))
			v1.Put("/draft", putDraftHandler(cfg))
		})
	})

	return r
}

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
