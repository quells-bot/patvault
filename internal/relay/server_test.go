package relay

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
)

// The guest pins the host key in known_hosts, so a key that changed across
// restarts would look exactly like an impersonation attempt and break every
// clone. This is the property that matters most about the file.
func TestLoadOrCreateHostKeyIsStableAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")

	first, created, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("first loadOrCreateHostKey: %v", err)
	}
	if !created {
		t.Error("created = false on first call, want true")
	}

	second, created, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateHostKey: %v", err)
	}
	if created {
		t.Error("created = true on second call, want false — the key must be reused")
	}

	wantFP := ssh.FingerprintSHA256(first.PublicKey())
	gotFP := ssh.FingerprintSHA256(second.PublicKey())
	if gotFP != wantFP {
		t.Errorf("fingerprint changed across restarts: %s then %s", wantFP, gotFP)
	}
}

func TestLoadOrCreateHostKeyIsEd25519(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	signer, _, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	if got := signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", got, ssh.KeyAlgoED25519)
	}
}

func TestLoadOrCreateHostKeyIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	if _, _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestLoadOrCreateHostKeyCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config", "relay_host_ed25519")
	if _, _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("host key not created: %v", err)
	}
}

// A corrupt key file must be reported, never silently replaced: regenerating it
// would break the guest's known_hosts pin without saying so.
func TestLoadOrCreateHostKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := loadOrCreateHostKey(path); err == nil {
		t.Fatal("loadOrCreateHostKey = nil error, want error on a corrupt key file")
	}
}

// newStore returns an OpenDB func and a keyring backed by a temp dir. The
// FileKeyring bootstraps its own master key on first use, so these tests never
// touch the OS keychain.
func newStore(t *testing.T) (func() (*db.DB, error), encrypt.Keyring) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "credentials.db")
	kr := encrypt.FileKeyring{Path: filepath.Join(dir, "master.key")}
	open := func() (*db.DB, error) { return db.Open(dbPath) }
	return open, kr
}

// storePAT encrypts pat and stores it for repo, exactly as 'patvault add' would.
// expires is a unix timestamp, or nil for a token that never expires.
func storePAT(t *testing.T, open func() (*db.DB, error), kr encrypt.Keyring, repo, pat string, expires *int64) {
	t.Helper()
	d, err := open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	key, err := encrypt.DeriveKey(mk, upstreamHost, repo)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	blob, err := encrypt.Encrypt(key, []byte(pat))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := d.Upsert(db.Credential{
		Host: upstreamHost, Path: repo, Username: "x-access-token",
		PAT: blob, Label: upstreamHost + "/" + repo,
		Created: time.Now().Unix(), Expires: expires,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

func TestResolveDecryptsStoredPAT(t *testing.T) {
	open, kr := newStore(t)
	storePAT(t, open, kr, "owner/repo", "ghp_secret_value", nil)
	s := &Server{OpenDB: open, Keyring: kr}

	req, err := s.resolve("owner/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if req.Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", req.Repo, "owner/repo")
	}
	if req.PAT != "ghp_secret_value" {
		t.Errorf("PAT = %q, want the decrypted token", req.PAT)
	}
}

func TestResolveAcceptsUnexpiredPAT(t *testing.T) {
	open, kr := newStore(t)
	future := time.Now().Add(24 * time.Hour).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_live", &future)
	s := &Server{OpenDB: open, Keyring: kr}

	req, err := s.resolve("owner/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if req.PAT != "ghp_live" {
		t.Errorf("PAT = %q, want %q", req.PAT, "ghp_live")
	}
}

func TestResolveRefusesMissingPAT(t *testing.T) {
	open, kr := newStore(t)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/never-added")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v (%T), want a *relayError", err, err)
	}
	if want := errNoPAT("owner/never-added").Error(); re.Error() != want {
		t.Errorf("message =\n%q\nwant\n%q", re.Error(), want)
	}
	if re.Exit() != 1 {
		t.Errorf("exit = %d, want 1", re.Exit())
	}
}

func TestResolveRefusesExpiredPAT(t *testing.T) {
	open, kr := newStore(t)
	past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_stale", &past)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/repo")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v (%T), want a *relayError", err, err)
	}
	want := "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then"
	if re.Error() != want {
		t.Errorf("message =\n%q\nwant\n%q", re.Error(), want)
	}
}

// The refusal must not leak the token it refused to use.
func TestResolveExpiredMessageDoesNotLeakPAT(t *testing.T) {
	open, kr := newStore(t)
	past := time.Now().Add(-time.Hour).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_super_secret", &past)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/repo")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	if strings.Contains(err.Error(), "ghp_super_secret") {
		t.Errorf("refusal leaked the PAT: %v", err)
	}
}

// A token expiring exactly now is expired: the spec's check is "<= now".
func TestResolveTreatsExpiryBoundaryAsExpired(t *testing.T) {
	open, kr := newStore(t)
	now := time.Now().Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_boundary", &now)
	s := &Server{OpenDB: open, Keyring: kr}

	if _, err := s.resolve("owner/repo"); err == nil {
		t.Fatal("resolve = nil error, want a refusal for a token expiring now")
	}
}
