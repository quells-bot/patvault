package encrypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	gokeyring "github.com/zalando/go-keyring"
)

// OSKeyring implements Keyring using the OS keychain via go-keyring.
type OSKeyring struct{}

func (OSKeyring) Get(service, account string) ([]byte, error) {
	s, err := gokeyring.Get(service, account)
	if err != nil {
		if errors.Is(err, gokeyring.ErrNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return base64.StdEncoding.DecodeString(s)
}

func (OSKeyring) Set(service, account string, key []byte) error {
	return gokeyring.Set(service, account, base64.StdEncoding.EncodeToString(key))
}

// GetOrCreateMasterKey returns the stored master key, creating and storing a
// fresh 256-bit key if none exists yet.
func GetOrCreateMasterKey(kr Keyring) ([]byte, error) {
	key, err := kr.Get(MasterKeyService, MasterKeyAccount)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("keyring get: %w", err)
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := kr.Set(MasterKeyService, MasterKeyAccount, key); err != nil {
		return nil, fmt.Errorf("keyring set: %w", err)
	}
	return key, nil
}
