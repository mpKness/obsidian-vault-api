package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func safeJoin(vaultRoot string, allowPrefixes []string, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	rel = strings.TrimPrefix(rel, "/")
	rel = strings.ReplaceAll(rel, "\\", "/")

	if strings.Contains(rel, "\x00") {
		return "", errors.New("invalid path")
	}

	// Optional allowlist (e.g. only allow reads from World/, Sessions/)
	if len(allowPrefixes) > 0 && rel != "" {
		ok := false
		for _, p := range allowPrefixes {
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

	joined := filepath.Join(vaultRoot, filepath.FromSlash(rel))
	clean := filepath.Clean(joined)

	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", errors.New("bad path")
	}

	// Must remain within vaultRoot
	rootWithSep := vaultRoot + string(os.PathSeparator)
	if abs != vaultRoot && !strings.HasPrefix(abs, rootWithSep) {
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
	return s[:n] + "..."
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
