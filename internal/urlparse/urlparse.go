package urlparse

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// NormalizePath strips a single trailing ".git" and any trailing slashes from
// a git URL path. Case is preserved (GitHub display case is meaningful).
func NormalizePath(path string) string {
	path = strings.TrimRight(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimRight(path, "/")
	return path
}

// ParseRepoURL parses an https repo URL into its host and normalized path.
// It requires an https scheme and a non-empty host and repository path.
func ParseRepoURL(rawURL string) (host, path string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", "", errors.New("URL must use https scheme")
	}
	host = u.Hostname()
	if host == "" {
		return "", "", errors.New("URL missing host")
	}
	path = strings.TrimPrefix(u.Path, "/")
	path = NormalizePath(path)
	if path == "" {
		return "", "", errors.New("URL missing repository path (expected https://github.com/owner/repo)")
	}
	return host, path, nil
}
