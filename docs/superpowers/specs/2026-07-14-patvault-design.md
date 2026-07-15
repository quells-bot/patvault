# Patvault: GitHub PAT Credential Helper

## Overview

Patvault is a Go CLI that implements the git credential helper API for GitHub Personal Access Tokens (PATs). It stores encrypted credentials in a SQLite database in the user's home directory, with the encryption key held in the OS keychain.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  git        │────▶│  patvault        │────▶│  SQLite     │
│  credential │     │  credential get  │     │  (~/.config │
│  helper     │     │  / store / erase │     │  /patvault/)│
└─────────────┘     └────────┬─────────┘     └──────┬──────┘
                             │                      │
                             │ (key derivation)     │ (encrypted BLOB)
                             ▼                      │
                      ┌──────────────┐              │
                      │  OS Keychain │◀─────────────┘
                      │  (Master Key)│   (AES-GCM decrypt)
                      └──────────────┘
```

## Data Model

### SQLite Schema

File: `~/.config/patvault/credentials.db`

```sql
CREATE TABLE IF NOT EXISTS credentials (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host      TEXT NOT NULL,
    path      TEXT NOT NULL DEFAULT '',
    username  TEXT NOT NULL DEFAULT '',
    pat       BLOB NOT NULL,           -- AES-GCM encrypted (nonce + ciphertext)
    label     TEXT NOT NULL DEFAULT '', -- human-friendly name, derived from URL
    created   INTEGER NOT NULL,         -- unix epoch seconds
    expires   INTEGER,                  -- unix epoch seconds, NULL = never
    UNIQUE(host, path, username)
);
```

- `pat` column: 12-byte GCM nonce + AES-256-GCM ciphertext + 16-byte auth tag
- `username` is the GitHub account name (e.g., `quells-bot`) for display purposes, not used in credential protocol auth
- `label` auto-generated from the URL on add (e.g., `github.com/quells-bot/patvault`)

## Encryption

### Master Key

- Generated once at first run: `crypto/rand` 256-bit (32 bytes)
- Stored in OS keychain via `zalando/go-keyring`: `service="patvault"`, `account="master-key"`
- macOS: Keychain, Linux: Secret Service (D-Bus/gnome-keyring)

### Per-Credential Key Derivation

```
HKDF-SHA256(master_key, salt=host|path, info="patvault-aes-key")
  → 256-bit per-credential AES key
```

- Deterministic: same host+path always produces the same key
- Salted per credential so one compromised key doesn't affect others
- No per-credential keychain round-trip — one keychain lookup, then pure computation

### Encryption Algorithm

- AES-256-GCM (authenticated encryption)
- Random 12-byte nonce generated per encryption, stored as first 12 bytes of BLOB
- GCM auth tag (16 bytes) appended by Go's `crypto/aes` + `crypto/cipher`

## CLI Commands

### `patvault add <repo-url> [--username] [--ttl-days N]`

Parses `<repo-url>` (must be `https://github.com/<owner>/<repo>`):
  - `host=github.com`
  - `path=<owner>/<repo>`
  - Prompts for PAT (hidden stdin via terminal.ReadPassword or equivalent)
  - Encrypts PAT, inserts/upserts into DB
  - `--ttl-days`: sets `expires = now + N*86400` (epoch seconds)
  - `--username`: GitHub account name (optional, extracted from URL path owner if absent)

### `patvault list [--show]`

Queries DB, decrypts PATs, outputs a table:
```
  Host         Path                          Username      Expires    PAT
  github.com   quells-bot/patvault           quells-bot    90 days    ghp_****
  github.com   another-org/some-repo         quells-bot    (never)    ghp_****
```
- PATs masked by default (`ghp_****`), `--show` reveals them
- Expired entries marked `(expired)` in `Expires` column
- `--prune` removes expired entries

### `patvault remove <repo-url> [--username]`

Parses URL, deletes matching row(s). If multiple match, requires `--username`.

### `patvault credential {get|store|erase}`

Implements the git credential helper protocol (invoked by git).

## Git Credential Protocol

### Input format (from git stdin)

```
protocol=https
host=github.com
path=quells-bot/some-repo
username=quells-bot
```

### `credential get`

1. Parse stdin for `protocol`, `host`, `path`, `username` fields
2. Query DB: `WHERE host=? AND path=? AND (username=? OR ?='') AND (expires IS NULL OR expires > unixepoch())`
3. If `host` is empty, exit 1
4. If `path` is missing and `useHttpPath` is disabled, git will not send it; match on host only
5. If no match, exit 1 (silent error) — git falls back to other helpers/prompts
6. If match found, decrypt PAT and output:

```
protocol=https
host=github.com
path=quells-bot/some-repo
username=x-access-token
password=ghp_abcdef123...
```

The `username=x-access-token` convention is sourced from the `gh` CLI — it tells GitHub's server the password is a token. Exit 0.

### `credential store`

Parse stdin for `host`, `path`, `password`. If `password` is present and `host` exists, encrypt and upsert into DB. Silently ignore otherwise.

### `credential erase`

Parse stdin for `host`, `path`, `username`. Delete any matching row(s). Idempotent: exit 0 even if no match.

## User-Facing Commands vs Git Helper

| Command | Trigger | Purpose |
|---|---|---|
| `add` | User CLI | Store a PAT for a repo |
| `list` | User CLI | View stored credentials |
| `remove` | User CLI | Delete a stored credential |
| `credential` | git | Protocol implementation; user never invokes directly |

### Git Configuration

```bash
git config --global credential.https://github.com.helper "patvault credential"
git config --global credential.https://github.com.useHttpPath true
```

## File Layout

```
~/.config/patvault/
  credentials.db      -- SQLite database

Installed binary:
  /usr/local/bin/patvault  (or wherever $PATH places it)
```

## Package Layout

```
cmd/patvault/main.go          -- entrypoint, cobra command routing
internal/
  db/
    sqlite.go                 -- DB open, migrations, query methods
    models.go                 -- Credential struct, JSON tags
  encrypt/
    encrypt.go                -- AES-GCM encrypt/decrypt, HKDF derivation
    keyring.go                -- master key get/create from OS keychain
  commands/
    add.go                    -- add subcommand
    list.go                   -- list subcommand
    remove.go                 -- remove subcommand
    credential.go             -- credential {get|store|erase} subcommand
```

## Error Handling

| Scenario | Behavior |
|---|---|
| No keychain available | `add` fails with message. Opt-in `patvault init --keychainless` stores master key as file (with warning). |
| `credential get` no match | Exit 1, silent. |
| `credential get` missing `host` | Exit 1 — insufficient context. |
| Expired credential in `get` | Treated as no match (SQL filter). Exit 1. |
| `credential store` no `password` | Silently ignore. |
| `credential erase` no match | Exit 0 (idempotent). |
| Malformed URL in `add` | Error with message, exit 1. |
| DB integrity failure | `PRAGMA integrity_check` on open. Error with path, suggest recovery. |
| Duplicate add (host+path+username) | Upsert — update PAT and timestamps. |

## Dependencies

| Package | Purpose |
|---|---|
| `zalando/go-keyring` | OS keychain access (macOS Keychain, Linux Secret Service) |
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO) |
| `golang.org/x/crypto/hkdf` | HKDF-SHA256 key derivation |
| `github.com/spf13/cobra` | CLI framework |
| Standard library `crypto/aes`, `crypto/cipher` | AES-256-GCM encryption |

## Testing

- **Unit tests**: In-memory SQLite for DB layer. Known-key test vectors for encryption. Table-driven tests for each command with `bytes.Buffer` I/O.
- **Keyring**: Mocked interface; no real keychain in unit tests.
- **Manual integration**: `echo -e "protocol=https\nhost=github.com\npath=owner/repo" | git credential fill`

## Non-Goals

- Non-GitHub git hosts (GitLab, Bitbucket, self-hosted)
- SSH key management
- OAuth token refresh flow
- GUI or TUI
- Cross-platform secret sharing (migrating DB between machines)
