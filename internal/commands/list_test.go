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
	if err := runList(d, kr, out, false, false); err != nil {
		t.Fatal(err)
	}
	body := out.String()
	if !strings.Contains(body, "github.com") || !strings.Contains(body, "owner/repo") {
		t.Errorf("output missing row: %q", body)
	}
	if !strings.Contains(body, "github_pat_****") {
		t.Errorf("PAT not masked: %q", body)
	}
	if strings.Contains(body, "github_pat_secret1234") {
		t.Errorf("full PAT leaked: %q", body)
	}
	if !strings.Contains(body, "(unknown)") {
		t.Errorf("expected (unknown) expiry: %q", body)
	}
}

func TestListShow(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	seedRow(t, d, kr, "github.com", "owner/repo", "github_pat_secret1234", nil)
	out := &bytes.Buffer{}
	if err := runList(d, kr, out, true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "github_pat_secret1234") {
		t.Errorf("expected full PAT with --show: %q", out.String())
	}
}

func TestListExpiredMarker(t *testing.T) {
	d := newTestDB(t)
	kr := &fakeKeyring{store: map[string][]byte{}}
	past := int64(1)
	seedRow(t, d, kr, "github.com", "old/repo", "github_pat_old", &past)
	out := &bytes.Buffer{}
	if err := runList(d, kr, out, false, false); err != nil {
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
	if err := runList(d, kr, &bytes.Buffer{}, false, true); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.List()
	if len(rows) != 1 || rows[0].Path != "new/repo" {
		t.Fatalf("prune left wrong rows: %+v", rows)
	}
}
