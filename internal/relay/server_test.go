package relay

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
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
