package encrypt

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// MasterKeyFileName is the file used by FileKeyring for keychainless mode.
const MasterKeyFileName = "master.key"

// FileKeyring stores the master key in a filesystem file (mode 0600). It is an
// opt-in, less-secure alternative to the OS keychain for headless systems that
// lack a Secret Service / Keychain daemon.
type FileKeyring struct {
	Path string
}

func (f FileKeyring) Get(service, account string) ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
}

func (f FileKeyring) Set(service, account string, key []byte) error {
	if dir := filepath.Dir(f.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(f.Path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600)
}
