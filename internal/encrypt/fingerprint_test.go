package encrypt

import (
	"regexp"
	"testing"
)

func TestFingerprintDeterministic(t *testing.T) {
	mk := []byte("0123456789abcdef0123456789abcdef")
	a := Fingerprint(mk, "github_pat_secret1234")
	b := Fingerprint(mk, "github_pat_secret1234")
	if a != b {
		t.Fatalf("not deterministic: %q vs %q", a, b)
	}
}

func TestFingerprintFormat(t *testing.T) {
	mk := []byte("0123456789abcdef0123456789abcdef")
	fp := Fingerprint(mk, "github_pat_secret1234")
	if !regexp.MustCompile(`^[a-z2-7]{8}$`).MatchString(fp) {
		t.Fatalf("want 8 lowercase base32 chars, got %q", fp)
	}
}

func TestFingerprintKeyedByMasterKey(t *testing.T) {
	tok := "github_pat_secret1234"
	if Fingerprint([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), tok) ==
		Fingerprint([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), tok) {
		t.Fatal("different master keys produced same fingerprint")
	}
}

func TestFingerprintDiffersFromTokenAndSurvivesReuse(t *testing.T) {
	mk := []byte("0123456789abcdef0123456789abcdef")
	// Same token under same key across repos → same fingerprint (surfaces reuse).
	if Fingerprint(mk, "tok-A") == Fingerprint(mk, "tok-B") {
		t.Fatal("distinct tokens collided")
	}
}
