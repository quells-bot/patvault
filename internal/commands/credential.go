package commands

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/urlparse"
)

// parseCredentialInput reads git's key=value pairs until EOF or a blank line.
func parseCredentialInput(r io.Reader) (map[string]string, error) {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		m[line[:idx]] = line[idx+1:]
	}
	return m, sc.Err()
}

// RunGet implements `git credential get`.
func RunGet(in io.Reader, out io.Writer, errOut io.Writer, d *db.DB, kr encrypt.Keyring) int {
	m, err := parseCredentialInput(in)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: parse input:", err)
		return 1
	}
	host := m["host"]
	if host == "" {
		return 1
	}
	path := urlparse.NormalizePath(m["path"])

	cred, err := d.Get(host, path)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: db:", err)
		return 1
	}
	if cred == nil {
		return 1 // no match, silent
	}
	if cred.Expires != nil && *cred.Expires <= time.Now().Unix() {
		fmt.Fprintf(errOut, "patvault: token for %s/%s expired %s; run 'patvault add' to refresh\n",
			host, path, time.Unix(*cred.Expires, 0).UTC().Format("2006-01-02"))
		return 1
	}

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: keyring:", err)
		return 1
	}
	key, err := encrypt.DeriveKey(mk, host, path)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: derive:", err)
		return 1
	}
	pat, err := encrypt.Decrypt(key, cred.PAT)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: decrypt:", err)
		return 1
	}

	username := m["username"]
	if username == "" {
		username = cred.Username
	}
	if username == "" {
		username = "x-access-token"
	}

	fmt.Fprintf(out, "protocol=https\nhost=%s\npath=%s\nusername=%s\npassword=%s\n",
		host, path, username, string(pat))
	return 0
}

// RunStore implements `git credential store` (change-aware).
func RunStore(in io.Reader, errOut io.Writer, d *db.DB, kr encrypt.Keyring) int {
	m, err := parseCredentialInput(in)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: parse input:", err)
		return 0
	}
	password := m["password"]
	host := m["host"]
	if password == "" || host == "" {
		return 0 // silently ignore
	}
	path := urlparse.NormalizePath(m["path"])

	existing, err := d.Get(host, path)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: db:", err)
		return 1
	}
	if existing != nil {
		mk, err := encrypt.GetOrCreateMasterKey(kr)
		if err != nil {
			fmt.Fprintln(errOut, "patvault: keyring:", err)
			return 1
		}
		key, err := encrypt.DeriveKey(mk, host, path)
		if err != nil {
			fmt.Fprintln(errOut, "patvault: derive:", err)
			return 1
		}
		current, err := encrypt.Decrypt(key, existing.PAT)
		if err == nil && string(current) == password {
			return 0 // unchanged → no-op, preserve expiry/metadata
		}
	}

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: keyring:", err)
		return 1
	}
	key, err := encrypt.DeriveKey(mk, host, path)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: derive:", err)
		return 1
	}
	blob, err := encrypt.Encrypt(key, []byte(password))
	if err != nil {
		fmt.Fprintln(errOut, "patvault: encrypt:", err)
		return 1
	}
	username := m["username"]
	if username == "" && existing != nil {
		username = existing.Username
	}
	label := host + "/" + path
	if existing != nil && existing.Label != "" {
		label = existing.Label
	}
	if err := d.Upsert(db.Credential{
		Host: host, Path: path, Username: username, PAT: blob,
		Label: label, Created: time.Now().Unix(), Expires: nil,
	}); err != nil {
		fmt.Fprintln(errOut, "patvault: upsert:", err)
		return 1
	}
	return 0
}

// RunErase implements `git credential erase`. Idempotent.
func RunErase(in io.Reader, errOut io.Writer, d *db.DB, kr encrypt.Keyring) int {
	m, err := parseCredentialInput(in)
	if err != nil {
		fmt.Fprintln(errOut, "patvault: parse input:", err)
		return 0
	}
	host := m["host"]
	path := urlparse.NormalizePath(m["path"])
	if host == "" {
		return 0
	}
	if err := d.Delete(host, path); err != nil {
		fmt.Fprintln(errOut, "patvault: delete:", err)
		return 1
	}
	return 0
}
