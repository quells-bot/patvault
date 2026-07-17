package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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

// runGit drives the real git binary at the relay.
//
// GIT_SSH_COMMAND starts with the word "ssh" on purpose: git sniffs the ssh
// variant from it and only adds "-o SendEnv=GIT_PROTOCOL" when it recognizes
// OpenSSH. That sniffing is exactly what makes the v2 gate reachable, so do not
// bypass it with ssh.variant.
func runGit(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_SSH_COMMAND=ssh -i "+keyPath+
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"+
			" -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		"GIT_TERMINAL_PROMPT=0",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %v unexpectedly succeeded:\n%s", args, out)
	}
	return string(out)
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
		name    string
		repo    string
		env     []string
		want    string
		wantNot string
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
