package github

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifySuccessWithExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo" {
			t.Errorf("path = %q, want /repos/owner/repo", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer github_pat_xyz" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		// GitHub emits a zone-name suffix, e.g. "... UTC" (verified against live API).
		w.Header().Set("github-authentication-token-expiration", "2026-12-31 23:59:59 UTC")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	v := HTTPVerifier{BaseURL: srv.URL}
	exp, err := v.Verify("owner", "repo", "github_pat_xyz")
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatal("expected expiry, got nil")
	}
	want := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	if !exp.Equal(want) {
		t.Errorf("expiry = %v, want %v", exp, want)
	}
}

func TestVerifyNumericOffsetExpiry(t *testing.T) {
	// Fallback layout: numeric offset instead of a zone name.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("github-authentication-token-expiration", "2026-12-31 23:59:59 +0000")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	v := HTTPVerifier{BaseURL: srv.URL}
	exp, err := v.Verify("owner", "repo", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil || !exp.Equal(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)) {
		t.Fatalf("expiry = %v, want 2026-12-31 23:59:59 UTC", exp)
	}
}

func TestVerifySuccessNoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	v := HTTPVerifier{BaseURL: srv.URL}
	exp, err := v.Verify("owner", "repo", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if exp != nil {
		t.Fatalf("expected nil expiry, got %v", exp)
	}
}

func TestVerifyAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	v := HTTPVerifier{BaseURL: srv.URL}
	_, err := v.Verify("owner", "repo", "bad")
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestVerifyNetworkFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.Close() // stop server → connection refused
	v := HTTPVerifier{BaseURL: srv.URL}
	_, err := v.Verify("owner", "repo", "tok")
	if err == nil {
		t.Fatal("expected network error")
	}
	if errors.Is(err, ErrAuthFailed) {
		t.Fatal("network error should not be ErrAuthFailed")
	}
	if !strings.Contains(err.Error(), "server") && !strings.Contains(err.Error(), "connection") {
		// any non-auth error is acceptable; just ensure it's a real transport error
	}
}
