package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// newSigner returns a fresh ed25519 signer and its authorized_keys line.
func newSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

// newTestServer builds a Server whose host key and allowlist live under
// t.TempDir, with allowed listed in the allowlist and an empty credential store.
func newTestServer(t *testing.T, allowedLine string) *Server {
	t.Helper()
	dir := t.TempDir()
	authKeys := filepath.Join(dir, "relay_authorized_keys")
	if err := os.WriteFile(authKeys, []byte(allowedLine), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	open, kr := newStore(t)
	return &Server{
		HostKeyPath:  filepath.Join(dir, "relay_host_ed25519"),
		AuthKeysPath: authKeys,
		OpenDB:       open,
		Keyring:      kr,
	}
}

// startRelay serves s on 127.0.0.1:0 and returns its address, shutting the
// server down when the test ends. A Serve that does not return on cancel fails
// the test: graceful shutdown is a requirement, not a nicety.
func startRelay(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v, want nil after a graceful shutdown", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return within 10s of cancellation")
		}
	})
	return ln.Addr().String()
}

// runExec runs one exec against the relay and returns the session's stderr and
// exit status.
//
// This is the precise instrument for exit codes: raw ssh propagates the relay's
// exit-status verbatim, whereas real git rewrites every remote refusal to its own
// 128 (see the plan's §"What is pinned"). The real-git gate asserts the message,
// not the code.
func runExec(t *testing.T, addr string, signer ssh.Signer, env map[string]string, cmd string) (stderr string, exit int) {
	t.Helper()
	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Errorf("dial: %v", err)
		return "", -1
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Errorf("new session: %v", err)
		return "", -1
	}
	defer sess.Close()

	for k, v := range env {
		if err := sess.Setenv(k, v); err != nil {
			t.Errorf("setenv %s: %v", k, err)
			return "", -1
		}
	}
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf

	switch err := sess.Run(cmd).(type) {
	case nil:
		return errBuf.String(), 0
	case *ssh.ExitError:
		return errBuf.String(), err.ExitStatus()
	default:
		t.Errorf("run %q: %v", cmd, err)
		return "", -1
	}
}

func TestServeRejectsUnlistedKey(t *testing.T) {
	_, allowedLine := newSigner(t)
	intruder, _ := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(intruder)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Fatal("dial with an unlisted key succeeded, want an auth failure")
	}
}

func TestServeAcceptsListedKey(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with a listed key: %v", err)
	}
	cc.Close()
}

// The relay presents the key it persisted, so a guest that pinned it stays
// pinned across restarts.
func TestServePresentsThePersistedHostKey(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)

	want, _, err := loadOrCreateHostKey(s.HostKeyPath)
	if err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	addr := startRelay(t, s)

	var got ssh.PublicKey
	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return nil
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	if gotFP, wantFP := ssh.FingerprintSHA256(got), ssh.FingerprintSHA256(want.PublicKey()); gotFP != wantFP {
		t.Errorf("host key = %s, want the persisted %s", gotFP, wantFP)
	}
}

// A relay serves git and nothing else: a shell (and, by the same default branch,
// a pty-req or a subsystem) is the disallowed-exec row, not a request to
// negotiate.
func TestServeRefusesShell(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	// A pipe, not a Buffer: Shell() returns the moment the request is refused,
	// which races the relay's stderr write. Reading the pipe to EOF waits for
	// the relay to write the refusal and close the channel, so this is
	// deterministic. (runExec can use a Buffer because Session.Run waits for the
	// exit-status and the output copies.)
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := sess.Shell(); err == nil {
		t.Error("Shell() = nil error, want a refusal")
	}
	msg, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if want := "patvault: only git fetch/push are permitted"; !strings.Contains(string(msg), want) {
		t.Errorf("stderr = %q, want it to contain %q", msg, want)
	}
}

// git-upload-archive would expose 'git archive --remote'. It is refused in this
// task because every exec is, and stays refused once Task 6 parses it.
func TestServeRefusesUploadArchive(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	stderr, exit := runExec(t, addr, signer, nil, `git-upload-archive '/owner/repo.git'`)
	if want := "patvault: only git fetch/push are permitted"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if exit != 128 {
		t.Errorf("exit = %d, want 128", exit)
	}
}

// Errors go to stderr, never stdout: git parses stdout as pkt-lines, and text
// injected there corrupts the parse.
func TestServeWritesRefusalToStderrNotStdout(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	_ = sess.Run(`git-upload-archive '/owner/repo.git'`)

	if outBuf.Len() != 0 {
		t.Errorf("stdout = %q, want no bytes — text on stdout corrupts git's pkt-line parse", outBuf.String())
	}
	if errBuf.Len() == 0 {
		t.Error("stderr is empty, want the refusal")
	}
}

// A goroutine per connection, per the base spec's concurrency note.
func TestServeHandlesConcurrentConnections(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stderr, exit := runExec(t, addr, signer, nil, `git-upload-archive '/owner/repo.git'`)
			if exit != 128 {
				t.Errorf("exit = %d, want 128", exit)
			}
			if !strings.Contains(stderr, "patvault:") {
				t.Errorf("stderr = %q, want a patvault refusal", stderr)
			}
		}()
	}
	wg.Wait()
}

func TestServeFailsOnMissingAllowlist(t *testing.T) {
	dir := t.TempDir()
	open, kr := newStore(t)
	s := &Server{
		HostKeyPath:  filepath.Join(dir, "relay_host_ed25519"),
		AuthKeysPath: filepath.Join(dir, "does-not-exist"),
		OpenDB:       open,
		Keyring:      kr,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if err := s.Serve(context.Background(), ln); err == nil {
		t.Fatal("Serve = nil error, want a startup error for a missing allowlist")
	}
}

// fakeBridge records what dispatch handed it. In this slice its main job is to
// fail the test when it is called at all: every refusal below must happen before
// anything upstream would be contacted.
type fakeBridge struct {
	mu      sync.Mutex
	fetched []Request
	pushed  []Request
	err     error
}

func (b *fakeBridge) Fetch(_ context.Context, req Request, _ io.Reader, out io.Writer) error {
	b.mu.Lock()
	b.fetched = append(b.fetched, req)
	b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	_, _ = out.Write([]byte("0008fetch"))
	return nil
}

func (b *fakeBridge) Push(_ context.Context, req Request, _ io.Reader, out io.Writer) error {
	b.mu.Lock()
	b.pushed = append(b.pushed, req)
	b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	_, _ = out.Write([]byte("0007push"))
	return nil
}

func (b *fakeBridge) calls() (fetched, pushed []Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Request(nil), b.fetched...), append([]Request(nil), b.pushed...)
}

// v2Env is what a real git sends before a fetch exec under protocol.version=2.
var v2Env = map[string]string{"GIT_PROTOCOL": "version=2"}

// The decisive gate test. Git announces version=1 under protocol.version=1, so a
// presence-only check would admit a v1 client into the v2 stateless pump. Each
// case here is a value a real git was observed to send (relay-ssh spike).
func TestDispatchV2GateComparesValue(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"v2 passes the gate", map[string]string{"GIT_PROTOCOL": "version=2"}, false},
		{"v1 is refused, not admitted", map[string]string{"GIT_PROTOCOL": "version=1"}, true},
		{"v0 sends nothing and is refused", nil, true},
		{"empty value is refused", map[string]string{"GIT_PROTOCOL": ""}, true},
		{"a value merely containing version=2 is refused", map[string]string{"GIT_PROTOCOL": "version=2x"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, allowedLine := newSigner(t)
			s := newTestServer(t, allowedLine)
			fb := &fakeBridge{}
			s.Bridge = fb
			storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
			addr := startRelay(t, s)

			stderr, exit := runExec(t, addr, signer, tc.env, `git-upload-pack '/owner/repo.git'`)
			fetched, _ := fb.calls()

			if !tc.wantErr {
				if len(fetched) != 1 {
					t.Fatalf("bridge fetched %d times, want 1; stderr=%q", len(fetched), stderr)
				}
				if exit != 0 {
					t.Errorf("exit = %d, want 0", exit)
				}
				return
			}
			want := "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)"
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, want)
			}
			if exit != 1 {
				t.Errorf("exit = %d, want 1", exit)
			}
			if len(fetched) != 0 {
				t.Errorf("bridge was called %d times for a refused fetch, want 0", len(fetched))
			}
		})
	}
}

// Push has no v2, so the gate must not apply to it: git sends no GIT_PROTOCOL
// before a receive-pack exec (relay-ssh spike).
func TestDispatchPushNeedsNoV2(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	fb := &fakeBridge{}
	s.Bridge = fb
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
	addr := startRelay(t, s)

	_, exit := runExec(t, addr, signer, nil, `git-receive-pack '/owner/repo.git'`)
	_, pushed := fb.calls()

	if len(pushed) != 1 {
		t.Fatalf("bridge pushed %d times, want 1", len(pushed))
	}
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
}

// The bridge receives a fully-resolved Request: the normalized repo and the
// decrypted PAT, with every check already passed.
func TestDispatchHandsBridgeAResolvedRequest(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	fb := &fakeBridge{}
	s.Bridge = fb
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_the_token", nil)
	addr := startRelay(t, s)

	// The .git suffix and leading slash are the user's URL's, and normalize away.
	if _, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`); exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	fetched, _ := fb.calls()
	if len(fetched) != 1 {
		t.Fatalf("bridge fetched %d times, want 1", len(fetched))
	}
	if fetched[0].Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", fetched[0].Repo, "owner/repo")
	}
	if fetched[0].PAT != "ghp_the_token" {
		t.Errorf("PAT = %q, want the decrypted token", fetched[0].PAT)
	}
}

// Every refusal below must happen before the bridge is reached: this is the
// no-upstream-contacted half of fail-before-first-byte, and it is exactly what
// makes this slice testable without an upstream.
func TestDispatchRefusesBeforeReachingTheBridge(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		cmd      string
		wantMsg  string
		wantExit int
		setup    func(t *testing.T, s *Server)
	}{
		{
			name:     "no stored PAT",
			env:      v2Env,
			cmd:      `git-upload-pack '/owner/never-added.git'`,
			wantMsg:  "patvault: no token stored for github.com/owner/never-added; run 'patvault add' on the host — this will not succeed until then",
			wantExit: 1,
		},
		{
			name: "expired PAT",
			env:  v2Env,
			cmd:  `git-upload-pack '/owner/stale.git'`,
			setup: func(t *testing.T, s *Server) {
				past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
				storePAT(t, s.OpenDB, s.Keyring, "owner/stale", "ghp_stale", &past)
			},
			wantMsg:  "patvault: token for github.com/owner/stale expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then",
			wantExit: 1,
		},
		{
			name:     "fetch without v2",
			cmd:      `git-upload-pack '/owner/repo.git'`,
			wantMsg:  "patvault: relay requires git wire protocol v2",
			wantExit: 1,
		},
		{
			name:     "upload-archive",
			env:      v2Env,
			cmd:      `git-upload-archive '/owner/repo.git'`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
		{
			name:     "unknown command",
			env:      v2Env,
			cmd:      `bash -c id`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
		{
			name:     "path traversal",
			env:      v2Env,
			cmd:      `git-upload-pack '/owner/../../etc/passwd'`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, allowedLine := newSigner(t)
			s := newTestServer(t, allowedLine)
			fb := &fakeBridge{}
			s.Bridge = fb
			storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
			if tc.setup != nil {
				tc.setup(t, s)
			}
			addr := startRelay(t, s)

			stderr, exit := runExec(t, addr, signer, tc.env, tc.cmd)
			if !strings.Contains(stderr, tc.wantMsg) {
				t.Errorf("stderr =\n%q\nwant it to contain\n%q", stderr, tc.wantMsg)
			}
			if exit != tc.wantExit {
				t.Errorf("exit = %d, want %d", exit, tc.wantExit)
			}
			fetched, pushed := fb.calls()
			if len(fetched) != 0 || len(pushed) != 0 {
				t.Errorf("bridge was reached (%d fetch, %d push) for a refusal that precedes it",
					len(fetched), len(pushed))
			}
		})
	}
}

// A nil Bridge is slice 2's normal state. It must refuse rather than panic.
func TestDispatchWithNoBridgeRefuses(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine) // Bridge left nil
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
	addr := startRelay(t, s)

	stderr, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`)
	if !strings.Contains(stderr, "patvault: relay failed internally") {
		t.Errorf("stderr = %q, want the internal-fault message", stderr)
	}
	if exit != 1 {
		t.Errorf("exit = %d, want 1", exit)
	}
}

// A host-side fault must not hand the client a message it cannot act on, and
// must not leak the fault's detail.
func TestDispatchMapsHostFaultToInternalError(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	s.Bridge = &fakeBridge{}
	s.OpenDB = func() (*db.DB, error) { return nil, errors.New("disk on fire") }
	addr := startRelay(t, s)

	stderr, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`)
	if !strings.Contains(stderr, "patvault: relay failed internally") {
		t.Errorf("stderr = %q, want the internal-fault message", stderr)
	}
	if strings.Contains(stderr, "disk on fire") {
		t.Errorf("stderr leaked the host-side cause: %q", stderr)
	}
	if exit != 1 {
		t.Errorf("exit = %d, want 1", exit)
	}
}

func TestClientErrorPassesRelayErrorsThrough(t *testing.T) {
	re := errNotV2()
	if got := clientError(re); got != re {
		t.Errorf("clientError(relayError) = %v, want the same error back", got)
	}
	if got := clientError(fmt.Errorf("wrapped: %w", re)); got != re {
		t.Errorf("clientError(wrapped relayError) = %v, want the unwrapped row", got)
	}
	if got := clientError(errors.New("db exploded")); got.Error() != errInternal().Error() {
		t.Errorf("clientError(plain error) = %q, want the internal-fault message", got.Error())
	}
}
