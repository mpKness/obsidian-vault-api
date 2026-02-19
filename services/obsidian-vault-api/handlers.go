package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type SearchHit struct {
	Path    string `json:"path"`
	Snippet string `json:"snippet"`
}

type BatchGetNotesRequest struct {
	Paths []string `json:"paths"`
}

type BatchNoteResult struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
	Error   string `json:"error,omitempty"`
}

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

func batchGetNotesHandler(cfg Config) http.HandlerFunc {
	const maxBatch = 50 // tweak as you like

	return func(w http.ResponseWriter, r *http.Request) {
		// Cap request body to avoid giant payloads
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB request cap
		defer r.Body.Close()

		var req BatchGetNotesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}

		if len(req.Paths) == 0 {
			writeErr(w, http.StatusBadRequest, "missing paths")
			return
		}
		if len(req.Paths) > maxBatch {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("too many paths (max %d)", maxBatch))
			return
		}

		results := make([]BatchNoteResult, 0, len(req.Paths))

		for _, p := range req.Paths {
			relPath := strings.TrimSpace(p)
			if relPath == "" {
				results = append(results, BatchNoteResult{Path: p, Error: "empty path"})
				continue
			}

			abs, err := safeJoin(cfg, relPath)
			if err != nil {
				results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: err.Error()})
				continue
			}

			ext := strings.ToLower(filepath.Ext(abs))
			if ext != ".md" && ext != ".markdown" {
				results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: "only markdown files allowed"})
				continue
			}

			fi, err := os.Stat(abs)
			if err != nil {
				if os.IsNotExist(err) {
					results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: "not found"})
				} else {
					results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: "stat failed"})
				}
				continue
			}
			if fi.Size() > cfg.MaxFileBytes {
				results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: "file too large"})
				continue
			}

			b, err := os.ReadFile(abs)
			if err != nil {
				results = append(results, BatchNoteResult{Path: filepath.ToSlash(relPath), Error: "read failed"})
				continue
			}

			results = append(results, BatchNoteResult{
				Path:    filepath.ToSlash(relPath),
				Content: string(b),
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(results),
			"results": results,
		})
	}
}
