# Repository Guidelines

## Project Overview

**patvault** — a Go CLI that implements the git credential helper protocol for
GitHub Personal Access Tokens. It stores PATs in a SQLite database encrypted
with AES-256-GCM, with the master key held in the OS keychain (or a file in
`--keychainless` mode). The problem: embedding PATs in remote URLs
(`https://<token>@github.com/owner/repo`) leaks them into `.git/config`, shell
history, and backups. patvault keeps the URL clean and the token encrypted.

First-class target: **fine-grained per-repo PATs**. Classic (account-wide) PATs
are not a design target.

## Architecture & Data Flow

Layered bottom-up, each package with one responsibility:

```
┌─────────────────────────────────────────────────────────┐
│  cmd/patvault/main.go                                   │
│    cobra root → subcommands → dependency injection      │
├─────────────────────────────────────────────────────────┤
│  internal/commands/                                     │
│    add, list, remove, init, credential {get,store,erase}│
├──────────────────┬──────────────────┬───────────────────┤
│  internal/db/    │ internal/encrypt/│ internal/github/  │
│  SQLite store    │ AES-GCM + HKDF   │ token verification│
│  internal/urlparse/ │ internal/gitconfig/                │
│  URL normalization  │ git config management              │
└─────────────────────┴───────────────────────────────────┘
```

**Data flow on `git push`:**

1. Git invokes `patvault credential get` with `host=github.com`,
   `path=owner/repo` on stdin.
2. `RunGet` queries SQLite for `(host, path)`.
3. Decrypts the PAT BLOB: master key from keychain → HKDF-SHA256 derive
   per-credential key → AES-256-GCM decrypt.
4. Outputs `username` + `password=<PAT>` on stdout.
5. Git uses the PAT as HTTP Basic Auth password.

**Encryption chain:**

- Master key: 256-bit random, stored in OS keychain (or `master.key` file).
- Per-credential key: `HKDF-SHA256(master_key, salt=host/path, info="patvault-aes-key")`.
- Encryption: AES-256-GCM, random 12-byte nonce prepended to ciphertext.
- Storage: `nonce || ciphertext || tag` in SQLite BLOB column.

## Key Directories

| Path | Purpose |
|------|---------|
| `cmd/patvault/main.go` | Entry point, cobra wiring, dependency injection |
| `internal/commands/` | CLI command implementations (`add`, `list`, `remove`, `init`, `credential`) |
| `internal/db/` | SQLite database — `Open`, `Upsert`, `Get`, `List`, `Delete`, `DeleteExpired` |
| `internal/encrypt/` | Keyring abstraction, AES-256-GCM encrypt/decrypt, HKDF derivation |
| `internal/github/` | Online PAT verification via GitHub REST API |
| `internal/gitconfig/` | Git config management (`useHttpPath`) |
| `internal/urlparse/` | URL parsing and path normalization |
| `docs/superpowers/` | Design spec and implementation plan |

## Development Commands

```bash
# Build
go build -o patvault ./cmd/patvault

# Run all tests
go test ./...

# Run tests with race detector
go test -race ./...

# Test a single package
go test ./internal/encrypt/...

# Test a single test function
go test -run TestRunGetMatch ./internal/commands/...

# Install
go install ./cmd/patvault
```

## Code Conventions & Common Patterns

### Dependency Injection

All command functions receive interfaces as parameters — no global state, no
`init()` side effects. Every external dependency is injectable:

```go
// commands/add.go
func NewAddCmd(open func() (*db.DB, error), kr encrypt.Keyring, v github.Verifier, r gitconfig.Runner)
```

Injected interfaces: `db.DB`, `encrypt.Keyring`, `github.Verifier`,
`gitconfig.Runner`. All are hand-written Go interfaces with 1-2 methods.

### Command Structure

Cobra commands are thin wrappers. Business logic lives in unexported
`run*` functions:

```go
// cmd/patvault/main.go
func buildAddCmd() *cobra.Command {
    return commands.NewAddCmd(openDB, selectKeyring(), github.HTTPVerifier{}, gitconfig.GitRunner{})
}

// internal/commands/add.go
func NewAddCmd(open func() (*db.DB, error), kr encrypt.Keyring, v github.Verifier, r gitconfig.Runner) *cobra.Command { … }
```

The `build*Cmd()` functions in `main.go` are the single place where production
implementations are wired. `selectKeyring()` auto-detects OS keychain vs file
keyring by checking if the master key file exists.

### Credential Helper Protocol Exit Codes

The `exitCode()` helper bridges cobra's error convention with git's expected
exit codes for credential helpers:

```go
func exitCode(code int) error {
    if code == 0 { return nil }
    os.Exit(code)  // bypass cobra's error printing
    return nil
}
```

- `0` → success (cobra nil error).
- `1` → no match / error (git falls back to other helpers or prompts).

### Error Handling

- Errors are wrapped with `fmt.Errorf("context: %w", err)` for sentinel errors
  (`ErrKeyNotFound`, `ErrAuthFailed`).
- Network errors propagate unwrapped (callers distinguish auth failure from
  connectivity failure).
- Commands that print to stderr on failure use `cmd.ErrOrStderr()`.
- Silently ignoring benign inputs (empty password, missing host) is done with
  early returns and exit 0.

### Path Normalization

All paths are normalized consistently on read and write:

```go
func NormalizePath(path string) string {
    path = strings.TrimRight(path, "/")
    path = strings.TrimSuffix(path, ".git")
    path = strings.TrimRight(path, "/")
    return path
}
```

Applied in `credential get`, `credential store`, `credential erase`, `add`,
`remove`, and `list`.

### Naming

- Interface types: `Keyring`, `Verifier`, `Runner` — single-method, no `-er` suffix.
- Tests: `Test<FunctionName><Scenario>` — e.g. `TestRunGetExpired`, `TestDeriveKeyDeterministic`.
- Table-driven tests with `tc.name` and `t.Run(tc.name, ...)`.
- Exported functions get doc comments; unexported helpers are self-documenting.

## Important Files

| File | Significance |
|------|--------------|
| `cmd/patvault/main.go` | Entry point, dependency wiring, `selectKeyring()`, `exitCode()` |
| `internal/commands/credential.go` | Core git protocol — `RunGet`, `RunStore`, `RunErase` |
| `internal/commands/add.go` | PAT add flow — URL parse → verify → encrypt → store |
| `internal/commands/init.go` | Master key bootstrap |
| `internal/encrypt/encrypt.go` | `DeriveKey`, `Encrypt`, `Decrypt` |
| `internal/encrypt/keyring.go` | `Keyring` interface, `OSKeyring`, `GetOrCreateMasterKey` |
| `internal/encrypt/filekeyring.go` | `FileKeyring` for `--keychainless` mode |
| `internal/db/sqlite.go` | SQLite schema, `Open`, `Upsert`, `Get`, `List`, `Delete`, `DeleteExpired` |
| `internal/db/models.go` | `Credential` struct |
| `internal/github/verify.go` | `Verifier` interface, `HTTPVerifier`, `ErrAuthFailed` |
| `internal/gitconfig/gitconfig.go` | `Runner` interface, `EnsureUseHTTPPath` |
| `internal/urlparse/urlparse.go` | `ParseRepoURL`, `NormalizePath` |

## Runtime/Tooling Preferences

- **Runtime**: Go 1.26.5 (see `go.mod`).
- **Package manager**: `go get` / `go install` — no third-party package manager.
- **Build**: `go build ./cmd/patvault` — single binary output.
- **No formatters configured** — standard `gofmt` is implicit.
- **No linters configured** — standard `go vet` is the baseline.
- **SQLite driver**: `modernc.org/sqlite` — pure Go, no CGo, no system SQLite.

## Testing & QA

### Framework

Standard library `testing` only. No `testify`, `gomock`, or external assertion
libraries.

### Test Patterns

- **Table-driven tests** with `{name, ...}` struct slices and `t.Run(tc.name, ...)`.
- **Direct function testing** — `run*` functions tested with injected
  dependencies, not via the cobra CLI pipeline.
- **Error paths tested** — wrong key, corrupt blob, auth failure, network
  failure, expired token, missing host, empty password.

### Fakes

All external dependencies are interface-injected, with hand-written fakes
(some duplicated across test packages):

| Interface | Fake | Where |
|-----------|------|-------|
| `encrypt.Keyring` | `fakeKeyring{store map[string][]byte}` | `commands/` and `encrypt/` tests |
| `github.Verifier` | `fakeVerifier{exp, err, called}` | `commands/add_test.go` |
| `gitconfig.Runner` | `fakeRunner{vals, sets}` | `gitconfig/` and `commands/` tests |
| `encrypt.Keyring` | `errKeyring{}` (always errors) | `encrypt/keyring_test.go` |

### Test Helpers

| Helper | Package | Purpose |
|--------|---------|---------|
| `newTestDB(t)` | `commands/`, `db/` | Temp-file SQLite DB with `t.Cleanup` |
| `seed(t, d, kr, host, path, pat, expires)` | `commands/` | Full pipeline: derive key → encrypt → upsert |
| `intPtr(v)` | `commands/`, `db/` | `int64` → `*int64` for `Expires` |
| `newFakeKeyring()` | Both | Allocates empty fake keyring |

### Coverage

- **Exhaustive**: `db/`, `encrypt/` (all 4 files), `github/`, `gitconfig/`.
- **Adequate**: `commands/` (5 command files, 12 test files) — thin on some
  edge cases (e.g., `--username` passthrough, `--ttl-days` + `--no-verify`).
- **Not tested**: `cmd/patvault/main.go` (thin cobra bootstrap, intentionally
  excluded).

### Running Tests

```bash
go test ./...              # all packages
go test -race ./...        # with race detector
go test -count=1 ./...     # disable test caching
```

### Credential Helper Registration

The correct git config for this project:

```bash
git config --global credential.helper '!patvault credential "$@"'
```

The `!` prefix is required because the helper name contains a space — without
it git looks for `git-credential-patvault credential` in PATH and fails.
`patvault add` also sets `credential.https://github.com.useHttpPath=true`.