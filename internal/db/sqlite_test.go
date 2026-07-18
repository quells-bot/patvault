package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func intPtr(v int64) *int64 { return &v }

func TestUpsertAndGet(t *testing.T) {
	d := newTestDB(t)
	exp := int64(2000000000)
	err := d.Upsert(Credential{
		Host: "github.com", Path: "owner/repo", Username: "owner",
		PAT: []byte("blob"), Label: "github.com/owner/repo",
		Created: 1000, Expires: &exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Get("github.com", "owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected row, got nil")
	}
	if got.Host != "github.com" || got.Path != "owner/repo" || got.Username != "owner" {
		t.Errorf("unexpected row: %+v", got)
	}
	if got.Expires == nil || *got.Expires != exp {
		t.Errorf("expires = %v, want %d", got.Expires, exp)
	}
}

func TestGetMissingReturnsNil(t *testing.T) {
	d := newTestDB(t)
	got, err := d.Get("github.com", "nope/repo")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for missing row")
	}
}

func TestUpsertReplacesExisting(t *testing.T) {
	d := newTestDB(t)
	d.Upsert(Credential{Host: "h", Path: "p", Username: "old", PAT: []byte("a"), Created: 1, Expires: intPtr(10)})
	d.Upsert(Credential{Host: "h", Path: "p", Username: "new", PAT: []byte("b"), Created: 2, Expires: nil})
	got, _ := d.Get("h", "p")
	if got.Username != "new" {
		t.Errorf("username = %q, want new", got.Username)
	}
	if string(got.PAT) != "b" {
		t.Errorf("pat = %q, want b", got.PAT)
	}
	if got.Expires != nil {
		t.Errorf("expires = %v, want nil", got.Expires)
	}
}

func TestList(t *testing.T) {
	d := newTestDB(t)
	d.Upsert(Credential{Host: "github.com", Path: "a/repo", PAT: []byte{}, Created: 1})
	d.Upsert(Credential{Host: "github.com", Path: "b/repo", PAT: []byte{}, Created: 2})
	rows, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("len = %d, want 2", len(rows))
	}
	if rows[0].Path != "a/repo" {
		t.Errorf("first row path = %q, want a/repo", rows[0].Path)
	}
}

func TestDelete(t *testing.T) {
	d := newTestDB(t)
	if err := d.Upsert(Credential{Host: "h", Path: "p", PAT: []byte("x"), Created: 1}); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete("h", "p"); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("h", "p")
	if got != nil {
		t.Fatal("row still present after delete")
	}
	// idempotent
	if err := d.Delete("h", "p"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteExpired(t *testing.T) {
	d := newTestDB(t)
	past := int64(1)
	d.Upsert(Credential{Host: "h", Path: "expired", PAT: []byte("x"), Created: 1, Expires: &past})
	d.Upsert(Credential{Host: "h", Path: "active", PAT: []byte("y"), Created: 1, Expires: intPtr(9999999999)})
	d.Upsert(Credential{Host: "h", Path: "unknown", PAT: []byte("z"), Created: 1, Expires: nil})
	n, err := d.DeleteExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1", n)
	}
	rows, _ := d.List()
	if len(rows) != 2 {
		t.Fatalf("remaining rows = %d, want 2", len(rows))
	}
}

func TestUpsertRoundTripsFingerprint(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Upsert(Credential{
		Host: "github.com", Path: "owner/repo", PAT: []byte{1, 2, 3},
		Fingerprint: "a1b2c3d4", TokenType: "github_pat", Created: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.Get("github.com", "owner/repo")
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Fingerprint != "a1b2c3d4" || got.TokenType != "github_pat" {
		t.Fatalf("round-trip lost columns: %+v", got)
	}
	rows, err := d.List()
	if err != nil || len(rows) != 1 || rows[0].Fingerprint != "a1b2c3d4" {
		t.Fatalf("list lost columns: %+v %v", rows, err)
	}
}

func TestMigrateAddsColumnsToOldDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// Build a pre-columns database by hand (the original 8-column schema).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL, path TEXT NOT NULL,
		username TEXT NOT NULL DEFAULT '', pat BLOB NOT NULL,
		label TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, expires INTEGER,
		UNIQUE(host, path));`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO credentials (host, path, pat, created)
		VALUES ('github.com', 'owner/legacy', x'0102', 1000)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Open through db.Open → migrate must ALTER in the new columns.
	d, err := Open(path)
	if err != nil {
		t.Fatalf("open/migrate old db: %v", err)
	}
	defer d.Close()
	got, err := d.Get("github.com", "owner/legacy")
	if err != nil || got == nil {
		t.Fatalf("legacy row unreadable after migrate: %v %v", got, err)
	}
	if got.Fingerprint != "" || got.TokenType != "" {
		t.Fatalf("legacy row should have empty new columns, got %+v", got)
	}
}

func TestUpdateFingerprint(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_ = d.Upsert(Credential{Host: "github.com", Path: "o/r", PAT: []byte{9}, Created: 1})
	if err := d.UpdateFingerprint("github.com", "o/r", "zz11zz11", "ghp"); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("github.com", "o/r")
	if got.Fingerprint != "zz11zz11" || got.TokenType != "ghp" {
		t.Fatalf("update failed: %+v", got)
	}
}
