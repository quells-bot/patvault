package relay

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// authorizedKeys is the set of public keys allowed to reach the relay, keyed by
// each key's SSH wire encoding.
//
// In v1 every authorized key may reach every repo that has a stored PAT. That is
// the design's known flat-authorization limitation; per-key scoping is v2's.
type authorizedKeys map[string]bool

// has reports whether key is in the allowlist. The comparison is over the wire
// encoding, so it does not depend on comment or option text.
func (a authorizedKeys) has(key ssh.PublicKey) bool {
	return a[string(key.Marshal())]
}

// loadAuthorizedKeys reads an OpenSSH authorized_keys file. Blank lines and
// #-comments are skipped.
//
// Every other line must parse: a typo would otherwise silently narrow the
// allowlist, leaving an agent refused for no visible reason. An allowlist with no
// keys is likewise an error, since serving one accepts nobody while looking
// healthy.
func loadAuthorizedKeys(path string) (authorizedKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized keys: %w", err)
	}
	keys := authorizedKeys{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if isBlankOrComment(line) {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		keys[string(key.Marshal())] = true
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s contains no keys; add one with 'patvault relay add-key'", path)
	}
	return keys, nil
}

// appendAuthorizedKey adds the public key in pubkeyFile to the allowlist,
// creating the file (0600) and its directory (0700) if needed. It reports
// added=false with a nil error when the key is already present, so running it
// twice does not duplicate a line.
func appendAuthorizedKey(allowlistPath, pubkeyFile string) (added bool, err error) {
	data, err := os.ReadFile(pubkeyFile)
	if err != nil {
		return false, fmt.Errorf("read public key: %w", err)
	}
	return appendAuthorizedKeyData(allowlistPath, data, pubkeyFile)
}

// appendAuthorizedKeyData is appendAuthorizedKey's core, parameterized over the
// already-read key bytes so the key can come from a file or from stdin. source
// labels the origin for the parse error only.
func appendAuthorizedKeyData(allowlistPath string, data []byte, source string) (added bool, err error) {
	key, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return false, fmt.Errorf("parse public key %s: %w", source, err)
	}

	existing, err := os.ReadFile(allowlistPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read authorized keys: %w", err)
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if isBlankOrComment(line) {
			continue
		}
		have, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			// A line that does not parse cannot be the key being added. Leave it
			// for loadAuthorizedKeys to report at serve time.
			continue
		}
		if bytes.Equal(have.Marshal(), key.Marshal()) {
			return false, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(allowlistPath), 0o700); err != nil {
		return false, fmt.Errorf("create config dir: %w", err)
	}
	f, err := os.OpenFile(allowlistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("open authorized keys: %w", err)
	}
	defer f.Close()

	var out strings.Builder
	// A hand-edited file may not end in a newline; do not weld onto its last line.
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		out.WriteString("\n")
	}
	// MarshalAuthorizedKey emits "<type> <base64>\n" and drops the comment.
	out.WriteString(strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"))
	if comment != "" {
		out.WriteString(" " + comment)
	}
	out.WriteString("\n")

	if _, err := f.WriteString(out.String()); err != nil {
		return false, fmt.Errorf("write authorized keys: %w", err)
	}
	return true, nil
}

// AddKey appends the public key in pubkeyFile to the allowlist at
// allowlistPath, reporting whether it was new. It is the exported face of
// appendAuthorizedKey for 'patvault relay add-key'.
func AddKey(allowlistPath, pubkeyFile string) (added bool, err error) {
	return appendAuthorizedKey(allowlistPath, pubkeyFile)
}

// AddKeyData appends the already-read public key bytes to the allowlist at
// allowlistPath, reporting whether it was new. It is the exported face of
// appendAuthorizedKeyData for 'patvault relay add-key' reading from stdin;
// source labels the origin for the parse error only.
func AddKeyData(allowlistPath string, data []byte, source string) (added bool, err error) {
	return appendAuthorizedKeyData(allowlistPath, data, source)
}

// isBlankOrComment reports whether a line carries no key.
func isBlankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}
