package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// loadOrCreateHostKey returns the relay's persistent ed25519 host key,
// generating it on first run. created reports whether this call generated it, so
// the caller can print the fingerprint for the operator to pin.
//
// The key is reused across restarts on purpose: the guest pins it in
// known_hosts, so a key that changed would be indistinguishable from an
// impersonation attempt. A corrupt file is therefore an error rather than a
// reason to regenerate.
func loadOrCreateHostKey(path string) (signer ssh.Signer, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("read host key: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate host key: %w", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "patvault relay host key")
	if err != nil {
		return nil, false, fmt.Errorf("marshal host key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, false, fmt.Errorf("write host key: %w", err)
	}
	signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, false, fmt.Errorf("host key signer: %w", err)
	}
	return signer, true, nil
}
