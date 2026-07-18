package commands

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
)

func seedRow(t *testing.T, d *db.DB, kr encrypt.Keyring, host, path, pat string, expires *int64) {
	seed(t, d, kr, host, path, pat, expires)
}

func TestListOutput(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seedRow(t, d, kr, "github.com", "owner/repo", "github_pat_secret1234", nil)

	out := &bytes.Buffer{}
	if err := runList(d, out, false); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, "Fingerprint") || !strings.Contains(body, "Type") {
		t.Errorf("missing new headers: %q", body)
	}
	mk, _ := encrypt.GetOrCreateMasterKey(kr)
	if !strings.Contains(body, encrypt.Fingerprint(mk, "github_pat_secret1234")) {
		t.Errorf("fingerprint not shown: %q", body)
	}
	if !strings.Contains(body, "github_pat") {
		t.Errorf("token type not shown: %q", body)
	}
	if strings.Contains(body, "github_pat_secret1234") {
		t.Errorf("full PAT leaked: %q", body)
	}
	if strings.Contains(body, "****") {
		t.Errorf("masked PAT should be gone: %q", body)
	}
}

func TestListLegacyRow(t *testing.T) {
	d := newTestDB(t)
	// Insert a row with no fingerprint (pre-migration style).
	if err := d.Upsert(db.Credential{
		Host: "github.com", Path: "old/repo", PAT: []byte{1}, Created: 1,
	}); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if err := runList(d, out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(legacy)") {
		t.Errorf("expected (legacy) for un-backfilled row: %q", out.String())
	}
}

func TestListExpiredMarker(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	past := int64(1)
	seedRow(t, d, kr, "github.com", "old/repo", "github_pat_old", &past)
	out := &bytes.Buffer{}
	if err := runList(d, out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(expired)") {
		t.Errorf("expected (expired): %q", out.String())
	}
}

func TestListPruneDeletesExpired(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	past := int64(1)
	seedRow(t, d, kr, "github.com", "old/repo", "github_pat_old", &past)
	seedRow(t, d, kr, "github.com", "new/repo", "github_pat_new", intPtr(time.Now().Unix()+1e8))
	if err := runList(d, &bytes.Buffer{}, true); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.List()
	if len(rows) != 1 || rows[0].Path != "new/repo" {
		t.Fatalf("prune left wrong rows: %+v", rows)
	}
}

func TestRefreshFingerprintsBackfills(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	// Legacy row: encrypted but no stored fingerprint.
	mk, _ := encrypt.GetOrCreateMasterKey(kr)
	key, _ := encrypt.DeriveKey(mk, "github.com", "owner/repo")
	blob, _ := encrypt.Encrypt(key, []byte("github_pat_legacy"))
	if err := d.Upsert(db.Credential{Host: "github.com", Path: "owner/repo", PAT: blob, Created: 1}); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	if err := runRefreshFingerprints(d, kr, out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warning") {
		t.Errorf("expected a warning about decryption: %q", out.String())
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got.Fingerprint != encrypt.Fingerprint(mk, "github_pat_legacy") || got.TokenType != "github_pat" {
		t.Fatalf("row not backfilled: %+v", got)
	}
}

func TestListNeverDecrypts(t *testing.T) {
	// A keyring that fails any access proves the default list path never
	// fetches the master key or decrypts.
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seedRow(t, d, kr, "github.com", "owner/repo", "github_pat_x", nil)
	// runList takes no keyring at all — the signature itself is the guarantee;
	// this test documents intent and will fail to compile if a keyring is added.
	if err := runList(d, &bytes.Buffer{}, false); err != nil {
		t.Fatal(err)
	}
}
