package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/quells-bot/patvault/internal/encrypt"
)

func TestFingerprintCommandMatchesList(t *testing.T) {
	kr := &fakeKeyring{store: map[string][]byte{}}
	const tok = "github_pat_secret1234"
	out := &bytes.Buffer{}
	if err := runFingerprint(kr, strings.NewReader(tok+"\n"), out); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out.String())
	mk, _ := encrypt.GetOrCreateMasterKey(kr)
	if want := encrypt.Fingerprint(mk, tok); got != want {
		t.Fatalf("fingerprint cmd = %q, want %q (must match list column)", got, want)
	}
}
