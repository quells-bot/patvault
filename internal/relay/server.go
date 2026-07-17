package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
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

// Request carries everything the bridge needs. By the time one is built, every
// fallible check — auth, exec parse, v2 gate, repo resolution, expiry, decrypt —
// has already passed.
type Request struct {
	Repo string // normalized "owner/repo", already shape-checked
	PAT  string // decrypted, already expiry-checked
}

// bridge is the seam to slice 3, named here so this slice cannot grow a shape
// slice 3 cannot use. Slice 3's exported Bridge struct satisfies it.
//
// It takes io.Reader/io.Writer rather than an ssh.Channel so the bridge never
// sees SSH and its tests need none. Neither method may write a byte to out until
// the upstream advertisement has returned 2xx — the fail-before-first-byte
// invariant, which is the bridge's to keep.
type bridge interface {
	Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error
	Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
}

// Server is the relay's SSH front door. Dependencies are injected in the
// repo's existing style: the DB open func and the Keyring, per the base spec's
// module layout.
type Server struct {
	// HostKeyPath is the persistent ed25519 host key the guest pins.
	HostKeyPath string
	// AuthKeysPath is the OpenSSH-format allowlist.
	AuthKeysPath string
	// OpenDB opens the credential store. One call per resolution.
	OpenDB func() (*db.DB, error)
	// Keyring holds the master key.
	Keyring encrypt.Keyring
	// Bridge relays to the upstream. Nil until slice 3 implements one, in which
	// case every otherwise-valid request is refused as an internal fault.
	Bridge bridge
	// Logger receives the operational log. Nil discards it.
	Logger *slog.Logger
}

// logger returns the operational logger, or one that discards.
func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// resolve looks up the stored PAT for repo and decrypts it, reusing the same
// keyring → derive → decrypt chain as the credential helper.
//
// The expiry check runs before the decrypt and before any upstream contact: a
// lapsed token is refused without a network round trip, which is what makes
// "expiry as a feature" cheap.
func (s *Server) resolve(repo string) (Request, error) {
	d, err := s.OpenDB()
	if err != nil {
		return Request{}, fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	cred, err := d.Get(upstreamHost, repo)
	if err != nil {
		return Request{}, fmt.Errorf("db get: %w", err)
	}
	if cred == nil {
		return Request{}, errNoPAT(repo)
	}
	if cred.Expires != nil && *cred.Expires <= time.Now().Unix() {
		return Request{}, errExpiredPAT(repo, time.Unix(*cred.Expires, 0))
	}

	mk, err := encrypt.GetOrCreateMasterKey(s.Keyring)
	if err != nil {
		return Request{}, fmt.Errorf("keyring: %w", err)
	}
	key, err := encrypt.DeriveKey(mk, upstreamHost, repo)
	if err != nil {
		return Request{}, fmt.Errorf("derive key: %w", err)
	}
	pat, err := encrypt.Decrypt(key, cred.PAT)
	if err != nil {
		return Request{}, fmt.Errorf("decrypt: %w", err)
	}
	return Request{Repo: repo, PAT: string(pat)}, nil
}
