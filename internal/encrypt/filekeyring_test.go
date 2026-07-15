package encrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyringRoundTrip(t *testing.T) {
	fk := FileKeyring{Path: filepath.Join(t.TempDir(), "master.key")}
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	if err := fk.Set(MasterKeyService, MasterKeyAccount, key); err != nil {
		t.Fatal(err)
	}
	got, err := fk.Get(MasterKeyService, MasterKeyAccount)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("round-trip mismatch")
	}
	info, _ := os.Stat(fk.Path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestFileKeyringGetMissing(t *testing.T) {
	fk := FileKeyring{Path: filepath.Join(t.TempDir(), "none.key")}
	_, err := fk.Get(MasterKeyService, MasterKeyAccount)
	if err != ErrKeyNotFound {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}

func TestFileKeyringCreatesParentDir(t *testing.T) {
	fk := FileKeyring{Path: filepath.Join(t.TempDir(), "nested", "dir", "master.key")}
	if err := fk.Set(MasterKeyService, MasterKeyAccount, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fk.Path); err != nil {
		t.Fatal("file not created")
	}
}
