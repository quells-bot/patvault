package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ErrKeyNotFound is returned by a Keyring Get when no key is stored.
var ErrKeyNotFound = errors.New("key not found in keyring")

// Keyring abstracts OS keychain access for the master key.
type Keyring interface {
	Get(service, account string) ([]byte, error)
	Set(service, account string, key []byte) error
}

// Master keychain storage identifiers.
const (
	MasterKeyService = "patvault"
	MasterKeyAccount = "master-key"
	keyInfo          = "patvault-aes-key"
)

// DeriveKey derives a deterministic 256-bit per-credential AES key from the
// master key using HKDF-SHA256, salted by host+path.
func DeriveKey(masterKey []byte, host, path string) ([]byte, error) {
	salt := []byte(host + "/" + path)
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, masterKey, salt, []byte(keyInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM and returns nonce||ciphertext||tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts a nonce||ciphertext||tag BLOB produced by Encrypt.
func Decrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}
