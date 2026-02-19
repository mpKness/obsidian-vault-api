package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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
		// rg returns exit code 1 for "no matches" - treat as empty success
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
