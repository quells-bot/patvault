package db

import (
	"path/filepath"
	"testing"
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
