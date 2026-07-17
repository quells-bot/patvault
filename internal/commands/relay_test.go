package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/relay"
)

// Binding a credential-injecting relay wider than the host-only interface is the
// one configuration mistake with a security consequence, so it is refused rather
// than guessed at.
func TestValidateListen(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"host-only interface", "192.168.64.1:2222", false},
		{"loopback", "127.0.0.1:2222", false},
		{"ipv6 loopback", "[::1]:2222", false},
		{"empty is a startup error", "", true},
		{"wildcard v4", "0.0.0.0:2222", true},
		{"wildcard v6", "[::]:2222", true},
		{"bare port means every interface", ":2222", true},
		{"no port", "192.168.64.1", true},
		{"hostname, not an IP", "localhost:2222", true},
		{"garbage", "not-an-address", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListen(tc.addr)
			if tc.wantErr && err == nil {
				t.Errorf("validateListen(%q) = nil, want an error", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateListen(%q) = %v, want nil", tc.addr, err)
			}
		})
	}
}

func newPubKeyFile(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	path := filepath.Join(dir, "agent.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return path
}

func TestRelayAddKeyAppendsAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	pubFile := newPubKeyFile(t, dir)
	allowlist := filepath.Join(dir, "relay_authorized_keys")

	run := func() string {
		cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), allowlist)
		var out strings.Builder
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"add-key", pubFile})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("add-key: %v", err)
		}
		return out.String()
	}

	if got := run(); !strings.Contains(got, "added") {
		t.Errorf("first add-key said %q, want it to report the key was added", got)
	}
	if got := run(); !strings.Contains(got, "already") {
		t.Errorf("second add-key said %q, want it to report a no-op", got)
	}

	data, err := os.ReadFile(allowlist)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	if n := len(strings.Fields(strings.TrimSpace(string(data)))); n != 2 {
		t.Errorf("allowlist = %q, want exactly one key line (type + base64)", data)
	}
}

func TestRelayAddKeyRejectsNonKey(t *testing.T) {
	dir := t.TempDir()
	notAKey := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notAKey, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"add-key", notAKey})
	if err := cmd.Execute(); err == nil {
		t.Fatal("add-key on a non-key file = nil error, want an error")
	}
}

func TestRelayServeRequiresListen(t *testing.T) {
	dir := t.TempDir()
	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"serve"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("serve without --listen = nil error, want a startup error")
	}
}

func TestRelayServeRejectsWildcardListen(t *testing.T) {
	dir := t.TempDir()
	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"serve", "--listen", "0.0.0.0:2222"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("serve --listen 0.0.0.0:2222 = nil error, want a refusal")
	}
}

// buildServeServer must wire a non-nil fetch Bridge pointed at GitHub, so that
// 'patvault relay serve' does fetches out of the box. (Push refuses until slice
// 4 — see relay.Bridge.Push.) The BaseURL is the one constant an operator must
// not have to set.
//
// The OpenDB func and FileKeyring are built inline from the real db.Open and
// encrypt.FileKeyring APIs (the same shape relay/server_test.go's newStore
// uses), so the test depends on no fictitious helper.
func TestBuildServeServerWiresFetchBridge(t *testing.T) {
	dir := t.TempDir()
	open := func() (*db.DB, error) { return db.Open(filepath.Join(dir, "test.db")) }
	kr := encrypt.FileKeyring{Path: filepath.Join(dir, "master.key")}
	srv := buildServeServer("/tmp/hostkey", "/tmp/authkeys", open, kr, slog.Default())
	if srv.Bridge == nil {
		t.Fatal("Bridge is nil; serve would refuse every fetch as an internal fault")
	}
	b, ok := any(srv.Bridge).(*relay.Bridge)
	if !ok {
		t.Fatalf("Bridge is %T, want *relay.Bridge", srv.Bridge)
	}
	if b.BaseURL != "https://github.com" {
		t.Errorf("BaseURL = %q, want https://github.com", b.BaseURL)
	}
	if b.Client == nil {
		t.Error("Client is nil")
	}
}
