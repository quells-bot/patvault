package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection for credential storage.
type DB struct {
	conn *sql.DB
}

// Open opens (creating the parent directory if needed) and migrates the
// credentials database, running an integrity check first.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite write safety across goroutines
	d := &DB{conn: conn}
	if err := d.integrityCheck(path); err != nil {
		conn.Close()
		return nil, err
	}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

// Close closes the database connection.
func (d *DB) Close() error { return d.conn.Close() }

func (d *DB) integrityCheck(path string) error {
	var ok string
	if err := d.conn.QueryRow("PRAGMA integrity_check").Scan(&ok); err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	if ok != "ok" {
		return fmt.Errorf("database integrity check failed for %s: %s (move the file aside and re-run 'patvault add' to start fresh)", path, ok)
	}
	return nil
}

func (d *DB) migrate() error {
	if _, err := d.conn.Exec(`
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT NOT NULL,
    path        TEXT NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    pat         BLOB NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created     INTEGER NOT NULL,
    expires     INTEGER,
    fingerprint TEXT NOT NULL DEFAULT '',
    token_type  TEXT NOT NULL DEFAULT '',
    UNIQUE(host, path)
);`); err != nil {
		return err
	}
	// SQLite lacks ADD COLUMN IF NOT EXISTS; add each only when missing so
	// pre-existing databases pick up the new columns.
	for _, col := range []struct{ name, ddl string }{
		{"fingerprint", "ALTER TABLE credentials ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''"},
		{"token_type", "ALTER TABLE credentials ADD COLUMN token_type TEXT NOT NULL DEFAULT ''"},
	} {
		has, err := d.hasColumn(col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := d.conn.Exec(col.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *DB) hasColumn(name string) (bool, error) {
	rows, err := d.conn.Query(`PRAGMA table_info(credentials)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			cname, ctype     string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if cname == name {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Upsert inserts or replaces the credential for (host, path).
func (d *DB) Upsert(c Credential) error {
	_, err := d.conn.Exec(`
INSERT INTO credentials (host, path, username, pat, label, created, expires, fingerprint, token_type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host, path) DO UPDATE SET
    username = excluded.username,
    pat = excluded.pat,
    label = excluded.label,
    created = excluded.created,
    expires = excluded.expires,
    fingerprint = excluded.fingerprint,
    token_type = excluded.token_type;`,
		c.Host, c.Path, c.Username, c.PAT, c.Label, c.Created, c.Expires,
		c.Fingerprint, c.TokenType)
	return err
}

// UpdateFingerprint sets the fingerprint and token_type for an existing row.
// Used by lazy backfill (credential get) and by list --refresh-fingerprints.
func (d *DB) UpdateFingerprint(host, path, fingerprint, tokenType string) error {
	_, err := d.conn.Exec(
		`UPDATE credentials SET fingerprint=?, token_type=? WHERE host=? AND path=?`,
		fingerprint, tokenType, host, path)
	return err
}

// Get returns the credential for (host, path) without filtering on expiry, or
// nil if no row exists.
func (d *DB) Get(host, path string) (*Credential, error) {
	row := d.conn.QueryRow(
		`SELECT id, host, path, username, pat, label, created, expires, fingerprint, token_type
		 FROM credentials WHERE host=? AND path=?`, host, path)
	c := &Credential{}
	var exp sql.NullInt64
	err := row.Scan(&c.ID, &c.Host, &c.Path, &c.Username, &c.PAT, &c.Label,
		&c.Created, &exp, &c.Fingerprint, &c.TokenType)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if exp.Valid {
		c.Expires = &exp.Int64
	}
	return c, nil
}

// List returns all credentials ordered by host then path.
func (d *DB) List() ([]Credential, error) {
	rows, err := d.conn.Query(
		`SELECT id, host, path, username, pat, label, created, expires, fingerprint, token_type
		 FROM credentials ORDER BY host, path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var exp sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Host, &c.Path, &c.Username, &c.PAT, &c.Label,
			&c.Created, &exp, &c.Fingerprint, &c.TokenType); err != nil {
			return nil, err
		}
		if exp.Valid {
			c.Expires = &exp.Int64
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Delete removes the credential for (host, path). Idempotent.
func (d *DB) Delete(host, path string) error {
	_, err := d.conn.Exec(`DELETE FROM credentials WHERE host=? AND path=?`, host, path)
	return err
}

// DeleteExpired removes all rows whose expires is set and in the past.
func (d *DB) DeleteExpired() (int64, error) {
	res, err := d.conn.Exec(`DELETE FROM credentials WHERE expires IS NOT NULL AND expires <= unixepoch()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
