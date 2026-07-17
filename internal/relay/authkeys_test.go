package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestKey returns a fresh ed25519 public key and its authorized_keys line
// (which ends in a newline, as ssh.MarshalAuthorizedKey emits it).
func newTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return sshPub, string(ssh.MarshalAuthorizedKey(sshPub))
}

// writeFile writes content to a fresh file under t.TempDir and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadAuthorizedKeysAcceptsListedKey(t *testing.T) {
	listed, listedLine := newTestKey(t)
	unlisted, _ := newTestKey(t)

	path := writeFile(t, "authorized_keys", listedLine)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(listed) {
		t.Error("listed key not in allowlist")
	}
	if keys.has(unlisted) {
		t.Error("unlisted key in allowlist")
	}
}

func TestLoadAuthorizedKeysSkipsBlanksAndComments(t *testing.T) {
	key, line := newTestKey(t)
	content := "# the agent's key\n\n   \n" + line + "\n# trailing comment\n"

	path := writeFile(t, "authorized_keys", content)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("loaded %d keys, want 1", len(keys))
	}
	if !keys.has(key) {
		t.Error("key not in allowlist")
	}
}

func TestLoadAuthorizedKeysMultipleKeys(t *testing.T) {
	k1, l1 := newTestKey(t)
	k2, l2 := newTestKey(t)

	path := writeFile(t, "authorized_keys", l1+l2)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(k1) || !keys.has(k2) {
		t.Error("both keys should be in the allowlist")
	}
}

func TestLoadAuthorizedKeysCRLFLines(t *testing.T) {
	key, line := newTestKey(t)
	// Windows-style CRLF line endings
	content := "# comment\r\n" + line + "\r\n"

	path := writeFile(t, "authorized_keys", content)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys with CRLF: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("loaded %d keys, want 1", len(keys))
	}
	if !keys.has(key) {
		t.Error("key not in allowlist with CRLF line endings")
	}
}

// A typo must not silently narrow the allowlist: an operator who mangled one
// line would otherwise get a relay that refuses that agent for no visible
// reason.
func TestLoadAuthorizedKeysRejectsUnparseableLine(t *testing.T) {
	_, line := newTestKey(t)
	path := writeFile(t, "authorized_keys", line+"ssh-ed25519 not-valid-base64!!\n")

	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on an unparseable line")
	}
}

// Serving with an empty allowlist would accept nobody while looking healthy.
func TestLoadAuthorizedKeysRejectsEmptyFile(t *testing.T) {
	path := writeFile(t, "authorized_keys", "# nothing here\n")
	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on a file with no keys")
	}
}

func TestLoadAuthorizedKeysMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on a missing file")
	}
}

func TestAppendAuthorizedKeyCreatesFile(t *testing.T) {
	key, line := newTestKey(t)
	pubFile := writeFile(t, "id_ed25519.pub", line)
	allowlist := filepath.Join(t.TempDir(), "nested", "relay_authorized_keys")

	added, err := appendAuthorizedKey(allowlist, pubFile)
	if err != nil {
		t.Fatalf("appendAuthorizedKey: %v", err)
	}
	if !added {
		t.Error("added = false, want true for a new key")
	}

	keys, err := loadAuthorizedKeys(allowlist)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(key) {
		t.Error("appended key is not in the allowlist")
	}

	info, err := os.Stat(allowlist)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestAppendAuthorizedKeyIsIdempotent(t *testing.T) {
	_, line := newTestKey(t)
	pubFile := writeFile(t, "id_ed25519.pub", line)
	allowlist := filepath.Join(t.TempDir(), "relay_authorized_keys")

	if _, err := appendAuthorizedKey(allowlist, pubFile); err != nil {
		t.Fatalf("first append: %v", err)
	}
	added, err := appendAuthorizedKey(allowlist, pubFile)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if added {
		t.Error("added = true on a duplicate, want false")
	}

	data, err := os.ReadFile(allowlist)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 1 {
		t.Errorf("allowlist has %d lines, want 1:\n%s", n, data)
	}
}

// An operator's hand-edited file may lack a trailing newline; appending must not
// weld the new key onto the last line.
func TestAppendAuthorizedKeyToFileWithoutTrailingNewline(t *testing.T) {
	k1, l1 := newTestKey(t)
	k2, l2 := newTestKey(t)

	dir := t.TempDir()
	allowlist := filepath.Join(dir, "relay_authorized_keys")
	if err := os.WriteFile(allowlist, []byte(strings.TrimSuffix(l1, "\n")), 0o600); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	pubFile := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubFile, []byte(l2), 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	if _, err := appendAuthorizedKey(allowlist, pubFile); err != nil {
		t.Fatalf("appendAuthorizedKey: %v", err)
	}
	keys, err := loadAuthorizedKeys(allowlist)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(k1) || !keys.has(k2) {
		t.Errorf("want both keys after append, got %d", len(keys))
	}
}

func TestAppendAuthorizedKeyRejectsNonKey(t *testing.T) {
	pubFile := writeFile(t, "not-a-key.pub", "this is not a public key\n")
	allowlist := filepath.Join(t.TempDir(), "relay_authorized_keys")

	if _, err := appendAuthorizedKey(allowlist, pubFile); err == nil {
		t.Fatal("appendAuthorizedKey = nil error, want error on a non-key file")
	}
	if _, err := os.Stat(allowlist); err == nil {
		t.Error("allowlist was created despite the key failing to parse")
	}
}
