package encrypt

import (
	"bytes"
	"errors"
	"testing"
)

type fakeKeyring struct {
	store map[string][]byte
}

func newFakeKeyring() *fakeKeyring {
	return &fakeKeyring{store: map[string][]byte{}}
}

func (f *fakeKeyring) Get(service, account string) ([]byte, error) {
	k, ok := f.store[service+"/"+account]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (f *fakeKeyring) Set(service, account string, key []byte) error {
	dup := make([]byte, len(key))
	copy(dup, key)
	f.store[service+"/"+account] = dup
	return nil
}

func TestGetOrCreateMasterKeyCreates(t *testing.T) {
	kr := newFakeKeyring()
	key, err := GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	// second call must return the same stored key
	key2, err := GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, key2) {
		t.Fatal("GetOrCreateMasterKey returned different key on second call")
	}
}

func TestGetOrCreateMasterKeyPreservesExisting(t *testing.T) {
	kr := newFakeKeyring()
	existing := []byte("preserved-32-bytes-key-aaaaaaaaa") // 32 bytes
	if len(existing) != 32 {
		t.Fatal("test data not 32 bytes")
	}
	kr.Set(MasterKeyService, MasterKeyAccount, existing)
	got, err := GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatal("existing key was overwritten")
	}
}

func TestGetOrCreateMasterKeyPropagatesOtherErrors(t *testing.T) {
	kr := &errKeyring{}
	_, err := GetOrCreateMasterKey(kr)
	if err == nil {
		t.Fatal("expected error from failing keyring")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatal("should not be ErrKeyNotFound")
	}
}

type errKeyring struct{}

func (errKeyring) Get(service, account string) ([]byte, error) {
	return nil, errors.New("keychain unavailable")
}
func (errKeyring) Set(service, account string, key []byte) error {
	return errors.New("keychain unavailable")
}
