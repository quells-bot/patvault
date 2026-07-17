package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// requireGit skips when the binaries this test drives are absent. The test is
// hermetic otherwise: it binds 127.0.0.1:0 and needs no credentials and no
// network, exactly as spike/relay-ssh does.
func requireGit(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"git", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH: %v", bin, err)
		}
	}
}

// newE2EKey returns an ed25519 private key and its ssh.Signer. Unlike
// server_test.go's newSigner, it hands back the raw private key too, because
// this test's client is the real ssh binary and needs the key on disk for -i.
func newE2EKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return priv, signer
}

// writeClientKey writes signer's private key in OpenSSH format and returns its
// path, for ssh -i.
func writeClientKey(t *testing.T, dir string, key any) string {
	t.Helper()
	blk, err := ssh.MarshalPrivateKey(key, "patvault relay test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

// gitEnv builds the environment for driving the real git/ssh client at the
// relay. Shared by runGit (expects failure) and runGitOK (expects success).
func gitEnv(keyPath string, extra []string) []string {
	env := append(os.Environ(),
		"GIT_SSH_COMMAND=ssh -i "+keyPath+
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"+
			" -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		"GIT_TERMINAL_PROMPT=0",
	)
	return append(env, extra...)
}

// runGit drives the real git binary at the relay and fails on success. Shared
// env setup delegates to gitEnv.
//
// GIT_SSH_COMMAND starts with the word "ssh" on purpose: git sniffs the ssh
// variant from it and only adds "-o SendEnv=GIT_PROTOCOL" when it recognizes
// OpenSSH. That sniffing is exactly what makes the v2 gate reachable, so do not
// bypass it with ssh.variant.
func runGit(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(keyPath, extraEnv)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %v unexpectedly succeeded:\n%s", args, out)
	}
	return string(out)
}

// runGitOK drives the real git binary at the relay and fails the test on error.
// The mirror of runGit (which fails on success); use this for the clone/fetch
// gate where success is expected.
func runGitOK(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(keyPath, extraEnv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}

// requireUploadPack skips when git-upload-pack is not installed. The e2e stub
// upstream shells out to it (as git http-backend does internally) so a real
// packfile — with real sideband framing the relay must not reframe — is produced
// by git itself, not invented by the test.
func requireUploadPack(t *testing.T) {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
		return
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-upload-pack")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("git-upload-pack not found at %s", bin)
	}
}

// uploadPackRepo runs git-upload-pack --stateless-rpc against repo, the way
// git http-backend does internally. When advertise is true it runs
// --advertise-refs (no stdin) and the caller prepends the smart-HTTP
// "# service=" banner+flush to the output. Otherwise it reads one v2 command
// from stdin and returns the response (refs, packfile, …) with sideband framing
// exactly as git emits it. GIT_PROTOCOL comes from the request so the stub
// mirrors the real server's protocol negotiation.
func uploadPackRepo(t *testing.T, repo string, advertise bool, gitProto string, stdin io.Reader) []byte {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-upload-pack")
	args := []string{"--stateless-rpc"}
	if advertise {
		args = append(args, "--advertise-refs")
	}
	args = append(args, repo)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "GIT_PROTOCOL="+gitProto)
	cmd.Stdin = stdin
	var stderr strings.Builder
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("git-upload-pack %v: %v\n%s", args, err, stderr.String())
	}
	return data
}

// newStubUpstreamServer stands up an httptest.Server that serves repo over the
// v2 smart-HTTP protocol by delegating to git-upload-pack. It is the relay's
// "stub upstream": real git produces the bytes (advertisement, refs, packfile),
// so the framing the relay pumps is ground truth, not invented. The stub serves
// one repo; the URL path is matched by suffix only.
func newStubUpstreamServer(t *testing.T, repo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gitProto := r.Header.Get("Git-Protocol")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "info/refs"):
			adv := uploadPackRepo(t, repo, true, gitProto, nil)
			// Prepend the smart-HTTP banner+flush that --advertise-refs omits
			// (git http-backend adds it; the stub replicates that). Probed
			// 2026-07-17: --advertise-refs emits the v2 advertisement with no banner.
			writePkt(w, "# service=git-upload-pack\n")
			writeFlush(w)
			w.Write(adv)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-upload-pack"):
			resp := uploadPackRepo(t, repo, false, gitProto, r.Body)
			w.Write(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// makeSourceRepo builds a work repo with one commit of real content and returns
// its path. Mirrors spike/relay-push-frame's makeRepo.
func makeSourceRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	mustRunGit(t, repo, "init", "-q", "-b", "main")
	mustRunGit(t, repo, "config", "user.email", "relay-e2e@example.invalid")
	mustRunGit(t, repo, "config", "user.name", "relay-e2e")
	if err := os.WriteFile(filepath.Join(repo, "data.txt"),
		[]byte("patvault relay slice 3 e2e\n"), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	mustRunGit(t, repo, "add", "data.txt")
	mustRunGit(t, repo, "commit", "-q", "-m", "initial")
	return repo
}

// mustRunGit runs git in dir and fails the test on error. No SSH env — for local
// repo setup only.
func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
}

// The slice gate. A real git, refused by a real relay, must show the operator the
// spec's patvault: line.
//
// Only the message is asserted. git rewrites every remote refusal to its own exit
// 128 and discards the relay's exit-status, so an exit-code assertion here would
// pass for the wrong reason; Tasks 5-6 pin the codes through an ssh client, which
// propagates them verbatim.
func TestRealGitIsRefusedWithThePatvaultMessage(t *testing.T) {
	requireGit(t)

	priv, signer := newE2EKey(t)
	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, priv)

	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
	storePAT(t, s.OpenDB, s.Keyring, "owner/stale", "ghp_stale", &past)
	storePAT(t, s.OpenDB, s.Keyring, "owner/live", "ghp_live", nil)
	addr := startRelay(t, s)

	tests := []struct {
		name string
		repo string
		env  []string
		want string
	}{
		{
			name: "no stored PAT",
			repo: "/owner/never-added.git",
			want: "patvault: no token stored for github.com/owner/never-added",
		},
		{
			name: "expired PAT",
			repo: "/owner/stale.git",
			want: "patvault: token for github.com/owner/stale expired 2026-07-01",
		},
		{
			// The gate must catch a real v0 client, not just a synthetic one.
			name: "fetch without protocol v2",
			repo: "/owner/live.git",
			env:  []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=0"},
			want: "patvault: relay requires git wire protocol v2",
		},
		{
			// The case the relay-ssh note says a presence-only gate admits.
			name: "fetch announcing v1 is not admitted",
			repo: "/owner/live.git",
			env:  []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=1"},
			want: "patvault: relay requires git wire protocol v2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "ssh://git@" + addr + tc.repo
			out := runGit(t, dir, keyPath, tc.env, "clone", url, filepath.Join(t.TempDir(), "clone"))
			if !strings.Contains(out, tc.want) {
				t.Errorf("git output did not carry the refusal.\nwant: %q\ngot:\n%s", tc.want, out)
			}
			// The refusal must never carry the token it refused to use.
			for _, secret := range []string{"ghp_stale", "ghp_live"} {
				if strings.Contains(out, secret) {
					t.Errorf("git output leaked a PAT:\n%s", out)
				}
			}
		})
	}
}

// An unlisted key never gets far enough to see a patvault: message — it is
// refused at authentication, which is the correct place.
func TestRealGitWithUnlistedKeyIsRefusedAtAuth(t *testing.T) {
	requireGit(t)

	_, listed := newE2EKey(t)
	intruderPriv, _ := newE2EKey(t)

	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, intruderPriv)

	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(listed.PublicKey())))
	storePAT(t, s.OpenDB, s.Keyring, "owner/live", "ghp_live", nil)
	addr := startRelay(t, s)

	out := runGit(t, dir, keyPath, nil,
		"clone", "ssh://git@"+addr+"/owner/live.git", filepath.Join(t.TempDir(), "clone"))
	if strings.Contains(out, "ghp_live") {
		t.Errorf("output leaked a PAT:\n%s", out)
	}
	if !strings.Contains(out, "Permission denied") && !strings.Contains(out, "publickey") {
		t.Errorf("want an authentication refusal, got:\n%s", out)
	}
}

// The slice-3 gate. A real git clone and an incremental fetch through the relay
// backed by a git-upload-pack stub upstream must succeed end to end. This is the
// anti-drift gate: the real client, the real relay, and a real (git-backed)
// upstream exchange real v2 bytes — including a sideband-framed packfile the
// relay must pump untouched.
//
// Protocol v2 is forced via GIT_CONFIG so the test does not depend on git's
// default (the relay requires version=2 for fetch).
func TestRealGitCloneAndIncrementalFetchThroughRelay(t *testing.T) {
	requireGit(t)
	requireUploadPack(t)

	priv, signer := newE2EKey(t)
	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, priv)

	// Upstream: a bare repo seeded from a real work repo with content.
	src := makeSourceRepo(t)
	bare := filepath.Join(t.TempDir(), "e2erepo.git")
	mustRunGit(t, src, "clone", "--bare", "-q", src, bare)
	upstream := newStubUpstreamServer(t, bare)

	// Relay: real Server, real Bridge pointed at the stub upstream.
	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	s.Bridge = &Bridge{Client: upstream.Client(), BaseURL: upstream.URL}
	storePAT(t, s.OpenDB, s.Keyring, "owner/e2erepo", "ghp_stub", nil)
	addr := startRelay(t, s)

	cloneURL := "ssh://git@" + addr + "/owner/e2erepo.git"
	v2 := []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=2"}

	// 1. A real clone through the relay.
	dest := filepath.Join(t.TempDir(), "clone")
	runGitOK(t, dir, keyPath, v2, "clone", "-q", cloneURL, dest)

	// The clone must carry the commit and its content.
	mustRunGit(t, dest, "log", "--oneline", "-n1")
	got, err := os.ReadFile(filepath.Join(dest, "data.txt"))
	if err != nil {
		t.Fatalf("read cloned data.txt: %v", err)
	}
	if !bytes.Contains(got, []byte("patvault relay slice 3 e2e")) {
		t.Errorf("cloned content mismatch: %q", got)
	}
	// The PAT the relay injected upstream must never reach the client.
	if bytes.Contains(got, []byte("ghp_stub")) {
		t.Errorf("cloned content leaked the PAT: %q", got)
	}

	// 2. An incremental fetch: add a commit upstream, fetch it through the relay.
	mustRunGit(t, src, "commit", "-q", "--allow-empty", "-m", "second")
	mustRunGit(t, src, "push", "-q", bare, "main")
	runGitOK(t, dest, keyPath, v2, "fetch", "-q", "origin")
	out := runGitOK(t, dest, keyPath, v2, "log", "--oneline", "origin/main")
	if !strings.Contains(out, "second") {
		t.Errorf("incremental fetch did not bring the new commit:\n%s", out)
	}
}
