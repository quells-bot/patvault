package commands

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/github"
)

type fakeVerifier struct {
	exp    *time.Time
	err    error
	called bool
}

func (f *fakeVerifier) Verify(owner, repo, pat string) (*time.Time, error) {
	f.called = true
	return f.exp, f.err
}

type fakeGitRunner struct {
	ensured bool
}

func (f *fakeGitRunner) Output(args ...string) ([]byte, error) {
	// pretend useHttpPath is not set
	return nil, errors.New("exit status 1")
}
func (f *fakeGitRunner) Run(args ...string) error {
	// record that we set it
	f.ensured = true
	return nil
}

func TestAddStoresVerifiedToken(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	v := &fakeVerifier{exp: &exp}
	r := &fakeGitRunner{}

	if err := runAdd(d, kr, v, r, bytes.NewBufferString("github_pat_secret\n"),
		"https://github.com/owner/repo", "", 0, false); err != nil {
		t.Fatal(err)
	}
	if !v.called {
		t.Fatal("verifier not called")
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got == nil {
		t.Fatal("row not stored")
	}
	if got.Expires == nil || *got.Expires != exp.Unix() {
		t.Errorf("expires = %v, want %d", got.Expires, exp.Unix())
	}
	if got.Username != "owner" {
		t.Errorf("username = %q, want owner", got.Username)
	}
	if got.Label != "github.com/owner/repo" {
		t.Errorf("label = %q", got.Label)
	}
	if !r.ensured {
		t.Error("useHttpPath not ensured")
	}
}

func TestAddAuthFailureDoesNotStore(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	v := &fakeVerifier{err: github.ErrAuthFailed}
	r := &fakeGitRunner{}
	err := runAdd(d, kr, v, r, bytes.NewBufferString("bad\n"),
		"https://github.com/owner/repo", "", 0, false)
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatalf("expected verification error, got %v", err)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got != nil {
		t.Fatal("row should not be stored on auth failure")
	}
}

func TestAddNetworkFailureStoresWithTTL(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	v := &fakeVerifier{err: errors.New("connection refused")}
	r := &fakeGitRunner{}
	before := time.Now().Unix()
	if err := runAdd(d, kr, v, r, bytes.NewBufferString("tok\n"),
		"https://github.com/owner/repo", "", 30, false); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got == nil {
		t.Fatal("row not stored on network failure")
	}
	if got.Expires == nil {
		t.Fatal("expected expires from ttl-days")
	}
	if *got.Expires < before+29*24*3600 {
		t.Errorf("expires too soon: %d", *got.Expires)
	}
}

func TestAddNoVerifySkipsVerification(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	v := &fakeVerifier{}
	r := &fakeGitRunner{}
	if err := runAdd(d, kr, v, r, bytes.NewBufferString("tok\n"),
		"https://github.com/owner/repo", "customuser", 0, true); err != nil {
		t.Fatal(err)
	}
	if v.called {
		t.Error("verifier should not be called with --no-verify")
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got.Username != "customuser" {
		t.Errorf("username = %q, want customuser", got.Username)
	}
	if got.Expires != nil {
		t.Errorf("expires = %v, want nil", got.Expires)
	}
}

func TestAddPopulatesFingerprintAndType(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	v := &fakeVerifier{}
	r := &fakeGitRunner{}
	const tok = "github_pat_secret1234"
	if err := runAdd(d, kr, v, r, bytes.NewBufferString(tok+"\n"),
		"https://github.com/owner/repo", "", 0, true); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got == nil {
		t.Fatal("row not stored")
	}
	if got.TokenType != "github_pat" {
		t.Errorf("token_type = %q, want github_pat", got.TokenType)
	}
	mk, _ := encrypt.GetOrCreateMasterKey(kr)
	if want := encrypt.Fingerprint(mk, tok); got.Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, want)
	}
}

func TestAddBadURL(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	err := runAdd(d, kr, &fakeVerifier{}, &fakeGitRunner{}, bytes.NewBufferString("x\n"),
		"http://github.com/owner/repo", "", 0, false)
	if err == nil {
		t.Fatal("expected error for non-https URL")
	}
}
