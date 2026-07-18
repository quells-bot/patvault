package commands

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
)

type fakeKeyring struct {
	store map[string][]byte
}

func (f *fakeKeyring) Get(service, account string) ([]byte, error) {
	k, ok := f.store[service+"/"+account]
	if !ok {
		return nil, encrypt.ErrKeyNotFound
	}
	return k, nil
}
func (f *fakeKeyring) Set(service, account string, key []byte) error {
	dup := make([]byte, len(key))
	copy(dup, key)
	f.store[service+"/"+account] = dup
	return nil
}

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func intPtr(v int64) *int64 { return &v }

func seed(t *testing.T, d *db.DB, kr encrypt.Keyring, host, path, pat string, expires *int64) {
	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatal(err)
	}
	key, err := encrypt.DeriveKey(mk, host, path)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encrypt.Encrypt(key, []byte(pat))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Upsert(db.Credential{
		Host: host, Path: path, Username: "owner", PAT: blob,
		Label: host + "/" + path, Created: 1000, Expires: expires,
		Fingerprint: encrypt.Fingerprint(mk, pat),
		TokenType:   tokenType(pat),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunGetMatch(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seed(t, d, kr, "github.com", "owner/repo", "github_pat_secret", nil)

	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\n")
	out := &bytes.Buffer{}
	code := RunGet(in, out, &bytes.Buffer{}, d, kr)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	body := out.String()
	if !strings.Contains(body, "password=github_pat_secret") {
		t.Errorf("output missing password: %q", body)
	}
	if !strings.Contains(body, "host=github.com") || !strings.Contains(body, "path=owner/repo") {
		t.Errorf("output missing host/path: %q", body)
	}
	if !strings.Contains(body, "username=owner") {
		t.Errorf("output missing username=owner: %q", body)
	}
}

func TestRunGetNoMatch(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	in := strings.NewReader("protocol=https\nhost=github.com\npath=other/repo\n")
	out := &bytes.Buffer{}
	if code := RunGet(in, out, &bytes.Buffer{}, d, kr); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("expected silent stdout, got %q", out.String())
	}
}

func TestRunGetExpired(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	past := int64(1)
	seed(t, d, kr, "github.com", "owner/repo", "github_pat_secret", &past)

	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\n")
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	if code := RunGet(in, out, errOut, d, kr); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("expired match should be silent on stdout, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "expired") {
		t.Errorf("stderr should warn about expiry: %q", errOut.String())
	}
}

func TestRunGetMissingHost(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	in := strings.NewReader("protocol=https\n")
	if code := RunGet(in, &bytes.Buffer{}, &bytes.Buffer{}, d, kr); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestRunGetEchoesProvidedUsername(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seed(t, d, kr, "github.com", "owner/repo", "tok", nil)
	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\nusername=customuser\n")
	out := &bytes.Buffer{}
	RunGet(in, out, &bytes.Buffer{}, d, kr)
	if !strings.Contains(out.String(), "username=customuser") {
		t.Errorf("should echo provided username, got %q", out.String())
	}
}

func TestRunStoreNew(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\nusername=owner\npassword=github_pat_new\n")
	if code := RunStore(in, &bytes.Buffer{}, d, kr); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got == nil {
		t.Fatal("row not stored")
	}
	if got.Expires != nil {
		t.Errorf("store should set expires=nil, got %v", got.Expires)
	}
}

func TestRunStoreUnchangedIsNoOp(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	exp := int64(9999999999)
	seed(t, d, kr, "github.com", "owner/repo", "github_pat_same", &exp)

	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\npassword=github_pat_same\n")
	if code := RunStore(in, &bytes.Buffer{}, d, kr); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got.Expires == nil || *got.Expires != exp {
		t.Errorf("unchanged store cleared expires: got %v, want %d", got.Expires, exp)
	}
}

func TestRunStoreEmptyPasswordIgnored(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\npassword=\n")
	if code := RunStore(in, &bytes.Buffer{}, d, kr); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got != nil {
		t.Fatal("empty password should not store a row")
	}
}

func TestRunErase(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seed(t, d, kr, "github.com", "owner/repo", "tok", nil)
	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\n")
	if code := RunErase(in, &bytes.Buffer{}, d, kr); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got != nil {
		t.Fatal("row should be deleted")
	}
}

func TestRunEraseIdempotent(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	in := strings.NewReader("protocol=https\nhost=github.com\npath=none/repo\n")
	if code := RunErase(in, &bytes.Buffer{}, d, kr); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}
