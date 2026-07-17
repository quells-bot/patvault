package relay

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A hand-edited allowlist may carry Windows CRLF line endings. The dedup pass
// in appendAuthorizedKey must still recognize an already-present key, so a
// second 'patvault relay add-key' is a no-op rather than a duplicate line —
// even though loadAuthorizedKeys is the function that explicitly strips \r.
// ssh.ParseAuthorizedKey tolerates a trailing \r, so this is a regression
// guard against anyone "simplifying" that contract away.
func TestAppendAuthorizedKeyDedupAgainstCRLFAllowlist(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")

	dir := t.TempDir()
	allow := filepath.Join(dir, "relay_authorized_keys")
	if err := os.WriteFile(allow, []byte("# comment\r\n"+line+"\r\n"), 0o600); err != nil {
		t.Fatalf("write CRLF allowlist: %v", err)
	}
	pubFile := filepath.Join(dir, "agent.pub")
	if err := os.WriteFile(pubFile, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	added, err := appendAuthorizedKey(allow, pubFile)
	if err != nil {
		t.Fatalf("appendAuthorizedKey against CRLF allowlist: %v", err)
	}
	if added {
		t.Error("added=true, want false: the key was already present and must not be duplicated")
	}
	data, err := os.ReadFile(allow)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	if got := strings.Count(string(data), "ssh-ed25519"); got != 1 {
		t.Errorf("allowlist has %d key lines, want 1 — dedup was defeated by CRLF:\n%s", got, data)
	}
}
