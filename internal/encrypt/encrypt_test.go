package encrypt

import (
	"bytes"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	k1, err := DeriveKey(master, "github.com", "owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d, want 32", len(k1))
	}
	k2, err := DeriveKey(master, "github.com", "owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveKey not deterministic for same inputs")
	}
	k3, err := DeriveKey(master, "github.com", "other/repo")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("DeriveKey produced identical keys for different paths")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	master := make([]byte, 32)
	key, err := DeriveKey(master, "github.com", "owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("github_pat_abcdef1234567890")
	blob, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// nonce (12) + plaintext + tag (16) > plaintext length
	if len(blob) <= len(plaintext) {
		t.Fatalf("blob too short: %d", len(blob))
	}
	got, err := Decrypt(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	master := make([]byte, 32)
	key, _ := DeriveKey(master, "github.com", "owner/repo")
	blob, _ := Encrypt(key, []byte("secret"))
	wrongKey, _ := DeriveKey(master, "github.com", "other/repo")
	if _, err := Decrypt(wrongKey, blob); err == nil {
		t.Fatal("Decrypt with wrong key succeeded; want auth failure")
	}
}

func TestDecryptCorruptFails(t *testing.T) {
	master := make([]byte, 32)
	key, _ := DeriveKey(master, "github.com", "owner/repo")
	blob, _ := Encrypt(key, []byte("secret"))
	blob[0] ^= 0xff // flip a nonce byte
	if _, err := Decrypt(key, blob); err == nil {
		t.Fatal("Decrypt of corrupt blob succeeded; want failure")
	}
}
