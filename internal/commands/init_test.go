package commands

import (
	"path/filepath"
	"testing"

	"github.com/quells-bot/patvault/internal/encrypt"
)

func TestInitKeychainlessCreatesKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "master.key")
	cmd := NewInitCmd(keyPath)
	cmd.SetArgs([]string{"--keychainless"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	fk := encrypt.FileKeyring{Path: keyPath}
	key, err := fk.Get(encrypt.MasterKeyService, encrypt.MasterKeyAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestInitKeychainlessIdempotent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "master.key")
	cmd1 := NewInitCmd(keyPath)
	cmd1.SetArgs([]string{"--keychainless"})
	if err := cmd1.Execute(); err != nil {
		t.Fatal(err)
	}
	fk := encrypt.FileKeyring{Path: keyPath}
	first, _ := fk.Get(encrypt.MasterKeyService, encrypt.MasterKeyAccount)

	cmd2 := NewInitCmd(keyPath)
	cmd2.SetArgs([]string{"--keychainless"})
	if err := cmd2.Execute(); err != nil {
		t.Fatal(err)
	}
	second, _ := fk.Get(encrypt.MasterKeyService, encrypt.MasterKeyAccount)
	if len(first) != 32 || len(second) != 32 {
		t.Fatal("keys not 32 bytes")
	}
}
