# Patvault: GitHub PAT Credential Helper

## Overview

Patvault is a Go CLI that implements the git credential helper API for GitHub
Personal Access Tokens (PATs). It stores encrypted credentials in a SQLite
database in the user's home directory, with the encryption key held in the OS
keychain.

The problem it solves: a common shortcut for authenticating pushes is to embed a
PAT directly in the remote URL —

```
git remote add origin https://<pat>@github.com/owner/repo
```

This bakes the token into `.git/config` in plaintext, and typically into shell
history, CI logs, and backups. Patvault is the safe version: the remote URL stays
clean (`https://github.com/owner/repo`), and git asks patvault for the token on
demand, which patvault supplies from encrypted storage.

### First-class target: fine-grained PATs

Fine-grained PATs scoped to a single repository with read/write **Contents**
access are the primary use case. Classic (account-wide) PATs are effectively
deprecated by GitHub and are **not** a design target. Consequently credentials
are scoped **strictly per repository**.

## How GitHub HTTPS + PAT authentication actually works

This section is normative background — the rest of the design depends on getting
it right.

- Git authenticates to GitHub over HTTPS using **HTTP Basic Auth**:
  `Authorization: Basic base64(username ":" password)`.
- **GitHub authenticates from the token and ignores the username.** The PAT goes
  in the **password** field; the username may be any non-empty string. GitHub
  identifies the caller from the token itself.
  (Ref: GitHub docs, *Managing your personal access tokens* — "although you are
  required to enter your username… the username is not used to authenticate.")
- **`x-access-token` is not magic.** It does not signal anything to the server;
  the server never reads the username. It is a human-readable placeholder
  convention that originated with GitHub **App installation** tokens
  (`https://x-access-token:TOKEN@github.com/...`). Any non-empty username works
  identically.
- `https://<pat>@github.com/owner/repo` works because it places the PAT in the
  **username** position with an empty password, and GitHub accepts a token in
  either field. Patvault instead supplies the token via the credential protocol,
  keeping it out of the URL.

**Design consequences:**

- The username is **display-only** metadata. It is never a matching key and is
  irrelevant to authentication. Patvault returns a `username` field to git only
  because git's `fill` requires one.
- Because the remote URL is clean, git normally sends **no username** in
  `credential get`, so there is nothing to match on but `host` + `path`.

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
    path      TEXT NOT NULL,            -- normalized: no ".git" suffix, no trailing slash
    username  TEXT NOT NULL DEFAULT '', -- display only; GitHub ignores it
    pat       BLOB NOT NULL,            -- AES-GCM encrypted (nonce + ciphertext + tag)
    label     TEXT NOT NULL DEFAULT '', -- human-friendly name, derived from URL
    created   INTEGER NOT NULL,         -- unix epoch seconds
    expires   INTEGER,                  -- unix epoch seconds; NULL = unknown / never
    UNIQUE(host, path)
);
```

- `pat` column: 12-byte GCM nonce + AES-256-GCM ciphertext + 16-byte auth tag.
- `username` is the GitHub login (e.g., `quells-bot`) for display only. It is
  **not** part of the unique key and never participates in matching.
- `label` auto-generated from the URL on add (e.g., `github.com/quells-bot/patvault`).
- `expires`: `NULL` means unknown (or effectively never). Fine-grained PATs always
  have a real expiry, populated by online verification on `add` (see below).

### Path normalization

Git sends the URL path **verbatim**, so `owner/repo`, `owner/repo.git`, and
`owner/repo/` are distinct strings that would fail to match each other. Patvault
normalizes on both write and read:

- strip a single trailing `.git`
- strip any trailing `/`
- preserve case (GitHub display case is meaningful)

The same normalization is applied in `add`, `credential get`, `credential store`,
`credential erase`, and `remove`.

## Encryption

### Master Key

- Generated once at first run: `crypto/rand` 256-bit (32 bytes).
- Stored in OS keychain via `zalando/go-keyring`: `service="patvault"`,
  `account="master-key"`.
- macOS: Keychain. Linux: Secret Service (D-Bus/gnome-keyring).

### Per-Credential Key Derivation

```
HKDF-SHA256(master_key, salt=host|path, info="patvault-aes-key")
  → 256-bit per-credential AES key
```

- Deterministic: same host+path always produces the same key.
- Salted per credential so one compromised key doesn't affect others.
- One keychain lookup per process, then pure computation — no per-credential
  keychain round-trip.

### Encryption Algorithm

- AES-256-GCM (authenticated encryption).
- Random 12-byte nonce per encryption, stored as the first 12 bytes of the BLOB.
- GCM auth tag (16 bytes) appended by Go's `crypto/aes` + `crypto/cipher`.

## Git Credential Protocol

### Input format (from git stdin)

```
protocol=https
host=github.com
path=quells-bot/some-repo
```

(git may also send `username=…` if one is embedded in the remote URL, but with the
clean-URL setup it normally does not.)

### `credential get`

1. Parse stdin for `protocol`, `host`, `path`, and optional `username`.
2. If `host` is empty, exit 1.
3. Normalize `path`.
4. Query:
   `WHERE host=? AND path=? AND (expires IS NULL OR expires > unixepoch())`.
5. **No match → exit 1** (silent on stdout; git falls back to other helpers or
   prompts the user). If a row exists for `(host, path)` but was filtered out as
   **expired**, additionally print a one-line **stderr** warning:
   `patvault: token for github.com/owner/repo expired 2026-06-01; run 'patvault add' to refresh`.
6. Match found → decrypt PAT and output:

```
protocol=https
host=github.com
path=quells-bot/some-repo
username=<see below>
password=ghp_… / github_pat_…
```

Exit 0.

**Username in the response** (returned only to satisfy git's protocol; GitHub
ignores it):

- If git **sent** a `username`, echo that exact value back — returning a different
  username than git already knows can make git reject the credential.
- Otherwise use the stored login; if none is stored, use the placeholder
  `x-access-token`.

### `credential store` — change-aware

Git calls `store` (via `credential approve`) after **every** successful
authentication — including when patvault itself just supplied the credential. A
naive upsert would therefore overwrite the accurate `expires`/`username` captured
on `add` with "unknown" on the very next push. So `store` is change-aware:

1. Parse stdin for `host`, `path` (normalize), `password`. If `password` empty or
   `host` empty, silently ignore (exit 0).
2. Look up `(host, path)`:
   - **exists and PAT unchanged** → **no-op** (preserves `expires` and metadata);
   - **new, or PAT changed** → upsert with `expires = NULL` (unknown — `store` has
     no online-verification path).

### `credential erase`

Parse stdin for `host`, `path` (normalize). Delete any matching row. Idempotent:
exit 0 even if no match.

## CLI Commands

### `patvault add <repo-url> [--username NAME] [--ttl-days N] [--no-verify]`

1. Parse and validate `<repo-url>` — must be
   `https://github.com/<owner>/<repo>`. Derive `host=github.com`,
   `path=<owner>/<repo>` (normalized). Malformed URL → error, exit 1.
2. Prompt for the PAT on hidden stdin (`term.ReadPassword` or equivalent).
3. **Online verification** (default; skip with `--no-verify`):
   - `GET https://api.github.com/repos/<owner>/<repo>` with
     `Authorization: Bearer <pat>`.
   - Non-2xx → error, do **not** store (catches typos, revoked tokens, and
     fine-grained tokens lacking access to *this* repo).
   - 2xx → read the `github-authentication-token-expiration` response header and
     store it as `expires`. (Endpoint chosen over `/user` so verification also
     confirms the token can reach *this specific repo*.)
   - Network failure (not an auth failure) → print a warning and fall back to
     `--ttl-days` if given, else `expires = NULL`; store anyway.
4. Ensure `credential.https://github.com.useHttpPath=true` is configured (set it,
   or prompt the user to). Without it git sends no path and per-repo matching
   cannot work.
5. Encrypt the PAT and upsert on `(host, path)`. `--username` overrides the stored
   display login (default: the repo owner).

### `patvault list [--show] [--prune]`

Queries the DB, decrypts PATs, prints a table:

```
  Host         Path                          Username      Expires     PAT
  github.com   quells-bot/patvault           quells-bot    ⚠ 5 days    github_pat_****
  github.com   another-org/some-repo         quells-bot    89 days     github_pat_****
  github.com   old-org/legacy                quells-bot    (expired)   github_pat_****
```

- PATs masked by default (`****` after the token-type prefix); `--show` reveals.
- `Expires` shown as relative time, with `⚠` when near (e.g., ≤ 7 days),
  `(expired)` when past, `(unknown)` when `NULL`.
- `--prune` deletes expired rows.

### `patvault remove <repo-url>`

Parse and normalize the URL, delete the matching `(host, path)` row. Idempotent.
No username disambiguation is needed (one credential per repo).

### `patvault credential {get|store|erase}`

Implements the git credential helper protocol above. Invoked by git, never
directly by the user.

## User-Facing Commands vs Git Helper

| Command      | Trigger  | Purpose                                          |
|--------------|----------|--------------------------------------------------|
| `add`        | User CLI | Store (and verify) a PAT for a repo              |
| `list`       | User CLI | View stored credentials                          |
| `remove`     | User CLI | Delete a stored credential                       |
| `credential` | git      | Protocol implementation; user never invokes it   |

### Git Configuration

```bash
git config --global credential.https://github.com.helper "patvault credential"
git config --global credential.https://github.com.useHttpPath true
```

`useHttpPath true` is **required**, not optional — per-repo matching depends on
git sending the path. `patvault add` ensures this is set.

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
    models.go                 -- Credential struct
  encrypt/
    encrypt.go                -- AES-GCM encrypt/decrypt, HKDF derivation
    keyring.go                -- master key get/create from OS keychain
  github/
    verify.go                 -- online token verification + expiry capture
  gitconfig/
    gitconfig.go              -- read/set credential.*.useHttpPath
  urlparse/
    urlparse.go               -- parse + normalize repo URLs and credential paths
  commands/
    add.go                    -- add subcommand
    list.go                   -- list subcommand
    remove.go                 -- remove subcommand
    credential.go             -- credential {get|store|erase} subcommand
```

## Error Handling

| Scenario                              | Behavior                                                                 |
|---------------------------------------|--------------------------------------------------------------------------|
| No keychain available                 | `add` fails with a message. Opt-in `patvault init --keychainless` stores the master key as a file (with warning). |
| `credential get` no match             | Exit 1, silent on stdout.                                                |
| `credential get` expired match        | Treated as no match (SQL filter); exit 1 + one-line stderr warning.      |
| `credential get` missing `host`       | Exit 1 — insufficient context.                                           |
| `credential store` no/empty `password`| Silently ignore, exit 0.                                                  |
| `credential store` PAT unchanged      | No-op (preserve captured expiry/metadata).                               |
| `credential erase` no match           | Exit 0 (idempotent).                                                      |
| `add` token verification non-2xx      | Error, do not store.                                                      |
| `add` network failure during verify   | Warn; fall back to `--ttl-days`/unknown expiry; store anyway.            |
| Malformed URL in `add`/`remove`       | Error with message, exit 1.                                              |
| DB integrity failure                  | `PRAGMA integrity_check` on open; error with path, suggest recovery.     |
| Duplicate `add` (host+path)           | Upsert — update PAT, expiry, and timestamps.                            |

## Dependencies

| Package                        | Purpose                                               |
|--------------------------------|-------------------------------------------------------|
| `zalando/go-keyring`           | OS keychain access (macOS Keychain, Linux Secret Service) |
| `modernc.org/sqlite`           | Pure-Go SQLite (no CGO)                               |
| `golang.org/x/crypto/hkdf`     | HKDF-SHA256 key derivation                            |
| `golang.org/x/term`            | Hidden PAT prompt                                     |
| `github.com/spf13/cobra`       | CLI framework                                         |
| stdlib `crypto/aes`, `crypto/cipher`, `net/http` | AES-256-GCM; token verification         |

## Testing

- **Unit tests**: in-memory SQLite for the DB layer; known-key test vectors for
  encryption; table-driven tests for each command with `bytes.Buffer` I/O.
- **Path normalization**: table-driven cases covering `.git` suffix, trailing
  slash, and their combinations across `add`/`get`/`store`/`erase`.
- **`store` change-awareness**: verify that a `store` with an unchanged PAT does
  not clear a previously captured `expires`.
- **Keyring**: mocked interface; no real keychain in unit tests.
- **GitHub verification**: mocked HTTP server returning the
  `github-authentication-token-expiration` header; test 2xx, non-2xx, and network
  failure paths.
- **Manual integration**:
  `echo -e "protocol=https\nhost=github.com\npath=owner/repo" | git credential fill`.

## Non-Goals

- Classic / account-wide PATs as a first-class scope.
- Non-GitHub git hosts (GitLab, Bitbucket, self-hosted).
- SSH key management.
- OAuth token refresh flow.
- GUI or TUI.
- Cross-machine secret sharing (migrating the DB between machines).
