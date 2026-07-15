package commands

import (
	"bytes"
	"testing"
)

func TestRemoveExisting(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seed(t, d, kr, "github.com", "owner/repo", "tok", nil)
	if err := runRemove(d, &bytes.Buffer{}, "https://github.com/owner/repo.git"); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("github.com", "owner/repo")
	if got != nil {
		t.Fatal("row should be deleted")
	}
}

func TestRemoveIdempotent(t *testing.T) {
	d := newTestDB(t)
	if err := runRemove(d, &bytes.Buffer{}, "https://github.com/none/repo"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveBadURL(t *testing.T) {
	d := newTestDB(t)
	if err := runRemove(d, &bytes.Buffer{}, "not-a-url"); err == nil {
		t.Fatal("expected error for bad URL")
	}
}
