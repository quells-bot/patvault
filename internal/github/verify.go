package github

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrAuthFailed indicates the token was rejected by GitHub (non-2xx response).
var ErrAuthFailed = errors.New("token verification failed")

// Verifier checks a PAT against GitHub and reports its expiry.
type Verifier interface {
	Verify(owner, repo, pat string) (expires *time.Time, err error)
}

// HTTPVerifier verifies tokens via the GitHub REST API. Network errors are
// returned directly (not wrapped in ErrAuthFailed) so callers can distinguish
// auth failure from connectivity failure.
type HTTPVerifier struct {
	Client  *http.Client
	BaseURL string // defaults to https://api.github.com
}

// headerTimeLayouts are the accepted formats of
// github-authentication-token-expiration. GitHub emits a zone-name suffix
// (e.g. "2026-08-11 06:18:47 UTC"); the numeric-offset form is a fallback.
var headerTimeLayouts = []string{
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05 -0700",
}

func (v HTTPVerifier) Verify(owner, repo, pat string) (*time.Time, error) {
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	base := v.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s", base, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: %s", ErrAuthFailed, resp.Status)
	}
	expStr := resp.Header.Get("github-authentication-token-expiration")
	if expStr == "" {
		return nil, nil
	}
	for _, layout := range headerTimeLayouts {
		if t, err := time.Parse(layout, expStr); err == nil {
			return &t, nil
		}
	}
	return nil, nil // unparseable → treat as unknown, not an error
}
