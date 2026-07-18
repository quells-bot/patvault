# patvault

Encrypted credential helper for GitHub Personal Access Tokens.

`patvault` stores PATs in a SQLite database encrypted with AES-256-GCM, with the
master key held in the OS keychain (or optionally a file). It implements the
[git credential helper protocol][gh-cred] so git can retrieve tokens on demand
without ever writing them to disk in plaintext.

The problem: embedding a PAT in the remote URL
(`https://<token>@github.com/owner/repo`) bakes it into `.git/config`, shell
history, and backups. `patvault` keeps the remote URL clean and the token
encrypted.

[gh-cred]: https://git-scm.com/docs/gitcredentials

## Install

```bash
go install github.com/quells-bot/patvault/cmd/patvault@latest
```

Requires Go 1.26+.

## Quick Start

### 1. Initialize

```bash
patvault init
```

Generates a 256-bit master key and stores it in the OS keychain (macOS
Keychain, Linux Secret Service / gnome-keyring / KDE Wallet).

On headless Linux VMs/containers without a D-Bus secret service, use
`--keychainless` to store the key in a file (`~/.config/patvault/master.key`,
mode 0600):

```bash
patvault init --keychainless
```

### 2. Add a credential

```bash
patvault add https://github.com/owner/repo
```

Prompts for the PAT (hidden input). By default it verifies the token against
the GitHub API, captures the expiry date from the
`github-authentication-token-expiration` header, and stores the encrypted token.

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | repo owner | Display login (GitHub ignores it) |
| `--ttl-days` | — | Fallback expiry in days when offline |
| `--no-verify` | false | Skip online token verification |

### 3. Register the git credential helper

```bash
git config --global credential.helper '!patvault credential "$@"'
```

This tells git to run `patvault credential get` / `store` / `erase` when it
needs credentials. The `!` prefix is required because the helper name contains
a space.

`patvault add` also sets `credential.https://github.com.useHttpPath=true` so
git sends the repository path in credential requests, enabling per-repo
matching.

### 4. Push

```bash
git push
```

Git will invoke `patvault credential get`, which looks up the encrypted token
by host+path, decrypts it, and returns it to git. The token never touches
disk.

## Commands

### `patvault add <repo-url>`

Store a PAT for a GitHub repository URL. Must be `https://github.com/owner/repo`.

### `patvault list [--show] [--prune]`

List stored credentials. PATs are masked by default (`github_pat_****`);
`--show` reveals them. `--prune` deletes expired entries.

```
  Host         Path                          Username      Expires     PAT
  github.com   quells-bot/patvault           quells-bot    ⚠ 5 days   github_pat_****
  github.com   another-org/some-repo         quells-bot    89 days     github_pat_****
  github.com   old-org/legacy                quells-bot    (expired)  github_pat_****
```

### `patvault remove <repo-url>`

Delete a stored credential.

### `patvault init [--keychainless]`

Initialize the master key. Run once before adding credentials.

### `patvault credential {get|store|erase}`

Git credential helper protocol implementation. Invoked by git, not by the user.

### `patvault relay serve [--listen <ip:port>] [--authorized-keys <path>] [--host-key <path>]`

Run the credential-injecting git relay in the foreground (see [Relay](#relay)).

### `patvault relay add-key <path-to-pubkey>`

Append an agent's SSH public key to the relay's allowlist.

## How it works

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

- **Encryption**: AES-256-GCM with a random 12-byte nonce per credential.
- **Key derivation**: HKDF-SHA256 derives a per-credential key from the master
  key salted with `host/path`, so one compromised key doesn't affect others.
- **Storage**: `~/.config/patvault/credentials.db` (SQLite). The PAT column
  holds nonce + ciphertext + auth tag; the master key never leaves the
  keychain (or the `master.key` file in `--keychainless` mode).
- **Path normalization**: trailing `.git` and `/` are stripped consistently on
  read and write so git's URL quirks don't cause mismatches.

## Relay

The **relay** lets an untrusted agent (a CI runner, a VM, a coding agent) use
your GitHub repos over git **without ever holding a token**. Instead of the
credential-helper flow above, the agent talks git over SSH to `patvault relay`,
which injects the stored PAT on the HTTPS leg to GitHub. The agent authenticates
with its own SSH key; the PAT never leaves the host.

```
agent git ──ssh (agent key)──▶ patvault relay ──https (PAT)──▶ github.com
```

### Setup (on the host that holds the PATs)

```bash
# 1. Store the PAT for each repo the agent may use (as above).
patvault add https://github.com/owner/repo

# 2. Authorize the agent's SSH public key.
patvault relay add-key ~/agent-keys/ci.pub

# 3. Serve. Bind an explicit host-only interface IP (never a wildcard).
patvault relay serve --listen 192.168.64.1:2222
```

The host key and allowlist default to `~/.config/patvault/` and persist across
restarts. `serve` runs in the foreground until SIGINT/SIGTERM.

### Use (on the agent)

Point the remote at the relay; the URL carries no secret:

```bash
git clone ssh://git@192.168.64.1:2222/owner/repo.git
git -C repo fetch
git -C repo push
```

Requires git wire protocol v2 for fetch (`git config --global protocol.version 2`,
the default since git 2.26). Supported transparently: clone, fetch, push
(including shallow `--depth`, partial `--filter=blob:none`, force, tag, and
branch-delete pushes). **Not** supported: git-LFS (its objects move over a
separate HTTPS endpoint, not the git channel) and `git archive --remote`.

## Target: fine-grained PATs

Fine-grained PATs scoped to a single repository are the primary use case.
Credentials are stored per `(host, path)`, so different tokens for different
repos coexist naturally.

## Files

| Path | Purpose |
|------|---------|
| `~/.config/patvault/credentials.db` | SQLite database of encrypted credentials |
| `~/.config/patvault/master.key` | Master key file (keychainless mode only, mode 0600) |