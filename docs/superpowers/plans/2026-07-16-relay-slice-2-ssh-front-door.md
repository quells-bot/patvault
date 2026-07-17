# Relay Slice 2 — The SSH Front Door That Refuses Everything Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the relay's SSH front door — host key, allowlist auth, `GIT_PROTOCOL` capture, exec dispatch, the v2 gate, repo resolution, expiry check, and the stderr + `exit-status` error surface — such that a **real `git`** driven at it gets the spec's `patvault:` refusal. **No upstream exists yet.**

**Architecture:** `errors.go` owns the spec's condition → (message, exit, retryable) table. `authkeys.go` loads and appends the OpenSSH allowlist. `server.go` is the SSH server: it persists an ed25519 host key, authenticates public keys against the allowlist, captures `env` requests, dispatches the `exec`, and — once every fallible check has passed — hands a `Request{Repo, PAT}` to a `bridge` seam that slice 3 implements. `commands/relay.go` wires `patvault relay serve` / `add-key`. Slice 1's `parseExec` is consumed here; slice 1's `pktline.go` is not (it is the bridge's).

**Tech Stack:** Go standard library (`context`, `crypto/ed25519`, `crypto/rand`, `encoding/pem`, `errors`, `fmt`, `io`, `log/slog`, `net`, `os`, `os/signal`, `path/filepath`, `strings`, `sync`, `syscall`, `testing`, `time`), plus existing dependencies `golang.org/x/crypto/ssh`, `github.com/spf13/cobra`, and the existing `internal/db`, `internal/encrypt`, `internal/urlparse` packages.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-15-relay-design.md` is authoritative; `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` (§"Slice 2 — the SSH front door that refuses everything") defines this slice's scope. Do not implement anything from slices 3–5 — no `bridge.go`, no HTTP client, no PAT injection, no `# service=` strip.
- Go version: module targets `go 1.26.5` (from `go.mod`). Do not lower it.
- **No new dependencies.** `go.mod` / `go.sum` must be unchanged at the end of this slice. Everything needed (`x/crypto/ssh`, `cobra`) is already required.
- **Testing framework:** standard library `testing` only. No `testify`, no `gomock`. Table-driven tests with `{name, ...}` struct slices and `t.Run(tc.name, ...)`, per `AGENTS.md` §Testing.
- **Package:** `internal/relay/` (`package relay`) and `internal/commands/` (`package commands`). Tests are in-package, matching how the repo tests unexported `run*` functions directly.
- **Visibility:** everything stays unexported **except** `relay.Server`, `relay.Request`, `relay.AddKey` (Task 7), and `commands.NewRelayCmd`. `Request` is exported because the design's §"The seam" names it as slice 3's interface. The `bridge` *interface* is unexported: slice 3's exported `Bridge` struct satisfies it.
- **Reuse, do not reimplement:** repo lookup goes through `internal/db`; the PAT is decrypted with `internal/encrypt` (`GetOrCreateMasterKey` → `DeriveKey` → `Decrypt`), exactly as `internal/commands/credential.go`'s `RunGet` does. Do not write a second decrypt path. Path normalization already happened in slice 1's `parseExec`.
- **Never log the PAT** (base spec §"Operational logging"). The operational log records fingerprint, op, repo, and outcome — nothing else.
- Naming: `Test<FunctionName><Scenario>` — e.g. `TestLoadAuthorizedKeysRejectsUnparseableLine`.
- Exported identifiers get doc comments; unexported helpers that encode a spike- or probe-pinned contract carry one too.
- Commit identity: `git config user.email noreply@anthropic.com && git config user.name Claude` before committing.
- Every commit message ends with the trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Gate for the whole slice: see §Slice gate. It includes a **real `git`** test, per the implementation design's anti-drift rule.

## What is pinned (these are the plan's inputs)

### From the spikes

From `docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md`:

1. **The v2 gate compares the VALUE, not the presence.** Git sends no
   `GIT_PROTOCOL` under `protocol.version=0`, but under `protocol.version=1` it
   *does* send one carrying `version=1`. A presence-only gate admits a v1 client
   into the v2 stateless pump. The test is `GIT_PROTOCOL == "version=2"`. The
   findings note records that this exact mistake was made once already and would
   have shipped a fail-open gate.
2. **`GIT_PROTOCOL` arrives before the exec**, so the relay knows the version at
   the moment it handles the exec.
3. **Request counts are noise.** The note's §Corrections item 3 records that the
   `[env env env exec]` ordering was the *caller's* locale being forwarded via
   `SendEnv`, not a git property. **Assert only that `GIT_PROTOCOL` precedes the
   exec — never a count of env requests.**
4. **`serveOnce`'s request loop** (`spike/relay-ssh/server.go`) is the named
   reference for this slice's channel-request handling, the same way
   `spike/relay-v2/pktline.go` was slice 1's reference. It is not production code
   (it accepts any key, captures instead of serving, handles one connection).

### From a probe run while writing this plan — read this, it changes the gate

The implementation design's slice table says slice 2's gate is "**real `git
clone`** gets the right `patvault:` stderr **+ exit code**". The second half is
false, and a plan that asserted it would fail. Probed against git 2.53.0 and
OpenSSH_10.2p1 with a throwaway SSH server that refused an exec with a known
`exit-status`:

| Relay sent `exit-status` | Real `git clone` reports | Raw `ssh` reports |
|---|---|---|
| 1 | **128** | **1** |
| 128 | **128** | **128** |

`git clone` maps *any* remote refusal to its own fatal convention (128) and
discards the relay's status — the relay's stderr line still reaches the user's
terminal verbatim, above git's own `fatal: Could not read from remote
repository.` Raw `ssh` propagates the status unchanged.

**Consequence, and it splits the gate in two:**

- **The `patvault:` message** is asserted through **real `git`** (Task 8). That
  is the half of the design's gate that holds, and it is the half that matters —
  it proves the wording the agent actually sees.
- **The exit status** is asserted through an **in-process `x/crypto/ssh`
  client** (Tasks 5–6), which reports it exactly. Asserting exit codes through
  `git` would pass for the wrong reason: every row would read 128 whatever the
  relay sent.

Do not "simplify" Task 8 by folding the exit-code assertions into it.

### Spec wording discrepancies to resolve (decided here, do not re-litigate)

1. **The v2 message appears twice in the base spec with different text.**
   §"Wire protocol" (the code block) has the trailing `(default since git 2.26)`;
   the §Errors table omits it. **Use the fuller §"Wire protocol" wording** — it is
   the more specific statement and the parenthetical is the actionable part for
   an agent.
2. **The error table's "No/expired PAT" is one row with a message that only fits
   *expired*** (it names an expiry date). A repo that was never `patvault add`ed
   has no date to name. This plan **splits the row into two messages** sharing
   the row's disposition (terminal, exit 1): `errExpiredPAT` names the date,
   `errNoPAT` does not. This is a gap fill, not a deviation — the spec has no
   wording for a case it lumped in.
3. **The spec's error table has no row for a host-side fault** (database
   unreadable, keychain locked, decrypt failure). These cannot be silent. This
   plan adds `errInternal` — exit 1, terminal, deliberately vague to the client
   (which can do nothing about it) with the detail going to the operational log.

### Scope decision: which error rows this slice writes

`errors.go` is slice 2's file per the implementation design, and that design says
it exists so there is "one file, one table". But three of the table's rows
(GitHub 401/403, 404, 5xx/network) describe **upstream** conditions, and this
slice has **no upstream**. Writing them now would be dead code whose wording the
spec itself flags as **unverified** (§"Unverified assumptions": "The
status→message mapping in §Errors is inferred, not observed" — slice 5 may
rewrite it).

**Decision: slice 2 writes only the rows slice 2 raises.** Slice 3 adds the
upstream rows to this same file. `errors.go` still ends up owning the whole
table; it just is not born complete. This is YAGNI applied to a table the spec
says is not yet trustworthy.

## File Structure

| Path | Responsibility |
|---|---|
| `internal/relay/errors.go` | `relayError` — the spec's condition → (message, exit, retryable) table. Constructors only; no logic. |
| `internal/relay/errors_test.go` | Each row against the spec's wording verbatim. |
| `internal/relay/authkeys.go` | `loadAuthorizedKeys` / `appendAuthorizedKey` — the OpenSSH-format allowlist. |
| `internal/relay/authkeys_test.go` | Parse, skip, reject, dedup, create. |
| `internal/relay/server.go` | `Server`, `Request`, the `bridge` seam, host key persistence, allowlist auth, the accept loop, graceful shutdown, the session request loop, exec dispatch, the v2 gate, repo resolution, and the stderr + `exit-status` surface. |
| `internal/relay/server_test.go` | Unit + in-process-ssh-client tests. **Exit codes are asserted here.** |
| `internal/relay/relay_e2e_test.go` | The anti-drift gate: **real `git`** refused with the right `patvault:` line. |
| `internal/commands/relay.go` | `patvault relay serve` / `add-key` cobra wiring; `--listen` validation. |
| `internal/commands/relay_test.go` | `--listen` validation; `add-key` end-to-end on a temp file. |

**`server.go` carries a lot** (host key + auth + accept loop + session + dispatch
+ resolution). That is deliberate: the base spec's §"Module layout" assigns
exactly that list to `server.go`, and the implementation design states `errors.go`
is "the only departure from that table". Do not add `hostkey.go` or `session.go`
— a second departure needs a design change, not an implementer's judgement call.

---

### Task 1: `errors.go` — the error table

**Files:**
- Create: `internal/relay/errors.go`
- Test: `internal/relay/errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  const upstreamHost = "github.com"

  type relayError struct { /* unexported fields */ }
  func (e *relayError) Error() string
  func (e *relayError) Exit() uint32
  func (e *relayError) Retryable() bool

  func errNoPAT(repo string) *relayError
  func errExpiredPAT(repo string, expires time.Time) *relayError
  func errNotV2() *relayError
  func errDisallowedExec() *relayError
  func errInternal() *relayError
  ```

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/errors_test.go`:

```go
package relay

import (
	"testing"
	"time"
)

// Each case is a row of the base spec's §"Errors and exit codes" table, with the
// message copied from the spec rather than paraphrased: the wording is the
// contract, because it is what tells the agent whether retrying can help.
func TestRelayErrorTable(t *testing.T) {
	tests := []struct {
		name      string
		err       *relayError
		want      string
		exit      uint32
		retryable bool
	}{
		{
			name:      "expired PAT",
			err:       errExpiredPAT("owner/repo", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)),
			want:      "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then",
			exit:      1,
			retryable: false,
		},
		{
			name:      "no PAT",
			err:       errNoPAT("owner/repo"),
			want:      "patvault: no token stored for github.com/owner/repo; run 'patvault add' on the host — this will not succeed until then",
			exit:      1,
			retryable: false,
		},
		{
			name:      "fetch without protocol v2",
			err:       errNotV2(),
			want:      "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)",
			exit:      1,
			retryable: false,
		},
		{
			name:      "disallowed exec",
			err:       errDisallowedExec(),
			want:      "patvault: only git fetch/push are permitted",
			exit:      128,
			retryable: false,
		},
		{
			name:      "internal fault",
			err:       errInternal(),
			want:      "patvault: relay failed internally; check the relay's log on the host",
			exit:      1,
			retryable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() =\n%q\nwant\n%q", got, tc.want)
			}
			if got := tc.err.Exit(); got != tc.exit {
				t.Errorf("Exit() = %d, want %d", got, tc.exit)
			}
			if got := tc.err.Retryable(); got != tc.retryable {
				t.Errorf("Retryable() = %v, want %v", got, tc.retryable)
			}
		})
	}
}

// The expiry date is rendered in UTC regardless of the stored instant's zone, so
// the message does not change with the host's locale.
func TestErrExpiredPATFormatsDateInUTC(t *testing.T) {
	zone := time.FixedZone("UTC+14", 14*60*60)
	// 2026-07-02 10:00 +14:00 is 2026-07-01 20:00 UTC.
	err := errExpiredPAT("owner/repo", time.Date(2026, 7, 2, 10, 0, 0, 0, zone))
	want := "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then"
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n%q\nwant\n%q", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: errExpiredPAT`, `undefined: errNoPAT`, `undefined: errNotV2`, `undefined: errDisallowedExec`, `undefined: errInternal`.

- [ ] **Step 3: Write the implementation**

Create `internal/relay/errors.go`:

```go
package relay

import (
	"fmt"
	"time"
)

// upstreamHost is the only forge the relay fronts. It is the host half of the
// stored credential's (host, path) key.
const upstreamHost = "github.com"

// relayError is one row of the base spec's §"Errors and exit codes" table: what
// the client is told, the exit status it is closed with, and whether retrying
// could ever help. Every refusal the relay sends a client is one of these.
//
// The message wording is a contract, not decoration: it is written to tell the
// calling agent whether to retry, so an agent does not loop on a terminal
// failure.
type relayError struct {
	msg       string
	exit      uint32
	retryable bool
}

func (e *relayError) Error() string { return e.msg }

// Exit is the SSH exit-status the channel is closed with. Git treats any
// non-zero as failure, so these are low-stakes: 1 for credential and upstream
// refusals, 128 (git's fatal convention) for protocol violations.
func (e *relayError) Exit() uint32 { return e.exit }

// Retryable reports whether the same request could succeed later without an
// operator touching the host. It mirrors the table's retry column and feeds the
// operational log.
func (e *relayError) Retryable() bool { return e.retryable }

// errNoPAT is the never-added half of the table's "No/expired PAT" row. The
// row's message names an expiry date, which a repo that was never added does not
// have; the disposition is the row's.
func errNoPAT(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: no token stored for %s/%s; run 'patvault add' on the host — this will not succeed until then",
			upstreamHost, repo),
		exit:      1,
		retryable: false,
	}
}

// errExpiredPAT is the expired half of the same row. The date is UTC so the
// message does not shift with the host's locale.
func errExpiredPAT(repo string, expires time.Time) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: token for %s/%s expired %s; run 'patvault add' on the host to refresh — this will not succeed until then",
			upstreamHost, repo, expires.UTC().Format("2006-01-02")),
		exit:      1,
		retryable: false,
	}
}

// errNotV2 refuses a fetch that did not announce protocol v2. The wording is the
// base spec's §"Wire protocol" code block, which carries the "(default since git
// 2.26)" the §Errors table drops — that parenthetical is the actionable part.
func errNotV2() *relayError {
	return &relayError{
		msg:       "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)",
		exit:      1,
		retryable: false,
	}
}

// errDisallowedExec is the one answer to every way an exec can be unacceptable:
// a shell, a pty, an unknown command, git-upload-archive, or an unparseable
// path. The distinctions are for the host's log, never the client's.
func errDisallowedExec() *relayError {
	return &relayError{
		msg:       "patvault: only git fetch/push are permitted",
		exit:      128,
		retryable: false,
	}
}

// errInternal covers a host-side fault — unreadable database, locked keychain,
// failed decrypt. The base spec's table has no row for these, and they cannot be
// silent. It is deliberately vague: the client can do nothing about any of them,
// and the detail belongs in the operational log.
func errInternal() *relayError {
	return &relayError{
		msg:       "patvault: relay failed internally; check the relay's log on the host",
		exit:      1,
		retryable: false,
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/errors.go internal/relay/errors_test.go
git commit -m "$(cat <<'EOF'
feat: the relay's error table, one row per refusal

Slice 2 of the relay implementation. The implementation design adds this file
because the base spec's module table has no home for the condition -> (message,
exit code, retryable) table.

Only the rows slice 2 can actually raise are here. The three upstream rows (401
/403, 404, 5xx) belong to slice 3, which has an upstream to raise them from --
and the spec flags their status->message mapping as inferred rather than
observed, so writing them now would be dead code with unverified wording.

Two gaps in the spec's table are filled rather than papered over. Its "No/expired
PAT" is one row whose message names an expiry date, which a repo that was never
added does not have, so that splits into errNoPAT and errExpiredPAT sharing the
row's disposition. And it has no row at all for a host-side fault -- unreadable
db, locked keychain, failed decrypt -- which cannot be silent, so errInternal
says nothing useful to a client that can do nothing about it and sends the detail
to the log instead.

The v2 message follows the spec's Wire protocol wording, not its error table's:
the table drops the "(default since git 2.26)" parenthetical, which is the part
an agent can act on.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `authkeys.go` — the allowlist

Standard OpenSSH `authorized_keys` format, parsed with `ssh.ParseAuthorizedKey`
(base spec §"Runtime, config, and concurrency"). `patvault relay add-key` appends
and de-duplicates; operators may also hand-edit.

**In v1 every authorized key may reach every repo with a stored PAT.** That is
the design's known flat-authorization limitation, not an oversight — do not
invent per-key scoping here.

**Files:**
- Create: `internal/relay/authkeys.go`
- Test: `internal/relay/authkeys_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  type authorizedKeys map[string]bool
  func (a authorizedKeys) has(key ssh.PublicKey) bool
  func loadAuthorizedKeys(path string) (authorizedKeys, error)
  func appendAuthorizedKey(allowlistPath, pubkeyFile string) (added bool, err error)
  ```
  `added` is false with a nil error when the key was already present, so `add-key`
  can report a no-op honestly.

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/authkeys_test.go`:

```go
package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestKey returns a fresh ed25519 public key and its authorized_keys line
// (which ends in a newline, as ssh.MarshalAuthorizedKey emits it).
func newTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return sshPub, string(ssh.MarshalAuthorizedKey(sshPub))
}

// writeFile writes content to a fresh file under t.TempDir and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadAuthorizedKeysAcceptsListedKey(t *testing.T) {
	listed, listedLine := newTestKey(t)
	unlisted, _ := newTestKey(t)

	path := writeFile(t, "authorized_keys", listedLine)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(listed) {
		t.Error("listed key not in allowlist")
	}
	if keys.has(unlisted) {
		t.Error("unlisted key in allowlist")
	}
}

func TestLoadAuthorizedKeysSkipsBlanksAndComments(t *testing.T) {
	key, line := newTestKey(t)
	content := "# the agent's key\n\n   \n" + line + "\n# trailing comment\n"

	path := writeFile(t, "authorized_keys", content)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("loaded %d keys, want 1", len(keys))
	}
	if !keys.has(key) {
		t.Error("key not in allowlist")
	}
}

func TestLoadAuthorizedKeysMultipleKeys(t *testing.T) {
	k1, l1 := newTestKey(t)
	k2, l2 := newTestKey(t)

	path := writeFile(t, "authorized_keys", l1+l2)
	keys, err := loadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(k1) || !keys.has(k2) {
		t.Error("both keys should be in the allowlist")
	}
}

// A typo must not silently narrow the allowlist: an operator who mangled one
// line would otherwise get a relay that refuses that agent for no visible
// reason.
func TestLoadAuthorizedKeysRejectsUnparseableLine(t *testing.T) {
	_, line := newTestKey(t)
	path := writeFile(t, "authorized_keys", line+"ssh-ed25519 not-valid-base64!!\n")

	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on an unparseable line")
	}
}

// Serving with an empty allowlist would accept nobody while looking healthy.
func TestLoadAuthorizedKeysRejectsEmptyFile(t *testing.T) {
	path := writeFile(t, "authorized_keys", "# nothing here\n")
	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on a file with no keys")
	}
}

func TestLoadAuthorizedKeysMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := loadAuthorizedKeys(path); err == nil {
		t.Fatal("loadAuthorizedKeys = nil error, want error on a missing file")
	}
}

func TestAppendAuthorizedKeyCreatesFile(t *testing.T) {
	key, line := newTestKey(t)
	pubFile := writeFile(t, "id_ed25519.pub", line)
	allowlist := filepath.Join(t.TempDir(), "nested", "relay_authorized_keys")

	added, err := appendAuthorizedKey(allowlist, pubFile)
	if err != nil {
		t.Fatalf("appendAuthorizedKey: %v", err)
	}
	if !added {
		t.Error("added = false, want true for a new key")
	}

	keys, err := loadAuthorizedKeys(allowlist)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(key) {
		t.Error("appended key is not in the allowlist")
	}

	info, err := os.Stat(allowlist)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestAppendAuthorizedKeyIsIdempotent(t *testing.T) {
	_, line := newTestKey(t)
	pubFile := writeFile(t, "id_ed25519.pub", line)
	allowlist := filepath.Join(t.TempDir(), "relay_authorized_keys")

	if _, err := appendAuthorizedKey(allowlist, pubFile); err != nil {
		t.Fatalf("first append: %v", err)
	}
	added, err := appendAuthorizedKey(allowlist, pubFile)
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if added {
		t.Error("added = true on a duplicate, want false")
	}

	data, err := os.ReadFile(allowlist)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 1 {
		t.Errorf("allowlist has %d lines, want 1:\n%s", n, data)
	}
}

// An operator's hand-edited file may lack a trailing newline; appending must not
// weld the new key onto the last line.
func TestAppendAuthorizedKeyToFileWithoutTrailingNewline(t *testing.T) {
	k1, l1 := newTestKey(t)
	k2, l2 := newTestKey(t)

	dir := t.TempDir()
	allowlist := filepath.Join(dir, "relay_authorized_keys")
	if err := os.WriteFile(allowlist, []byte(strings.TrimSuffix(l1, "\n")), 0o600); err != nil {
		t.Fatalf("seed allowlist: %v", err)
	}
	pubFile := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubFile, []byte(l2), 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	if _, err := appendAuthorizedKey(allowlist, pubFile); err != nil {
		t.Fatalf("appendAuthorizedKey: %v", err)
	}
	keys, err := loadAuthorizedKeys(allowlist)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if !keys.has(k1) || !keys.has(k2) {
		t.Errorf("want both keys after append, got %d", len(keys))
	}
}

func TestAppendAuthorizedKeyRejectsNonKey(t *testing.T) {
	pubFile := writeFile(t, "not-a-key.pub", "this is not a public key\n")
	allowlist := filepath.Join(t.TempDir(), "relay_authorized_keys")

	if _, err := appendAuthorizedKey(allowlist, pubFile); err == nil {
		t.Fatal("appendAuthorizedKey = nil error, want error on a non-key file")
	}
	if _, err := os.Stat(allowlist); err == nil {
		t.Error("allowlist was created despite the key failing to parse")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: loadAuthorizedKeys`, `undefined: appendAuthorizedKey`.

- [ ] **Step 3: Write the implementation**

Create `internal/relay/authkeys.go`:

```go
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
	key, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return false, fmt.Errorf("parse public key %s: %w", pubkeyFile, err)
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

// isBlankOrComment reports whether a line carries no key.
func isBlankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/authkeys.go internal/relay/authkeys_test.go
git commit -m "$(cat <<'EOF'
feat: the relay's OpenSSH authorized-keys allowlist

Load and append, in the standard format, so an operator can hand-edit the file
and 'patvault relay add-key' can append to it without duplicating.

Two failure modes are errors rather than shrugs, because both would otherwise
narrow the allowlist invisibly: a line that does not parse fails the load instead
of being skipped (a typo would silently lock an agent out), and a file with no
keys at all fails too, since serving it accepts nobody while looking healthy.

Keys compare by wire encoding, so comments and options do not affect identity.
Appending tolerates a hand-edited file with no trailing newline instead of
welding the new key onto the last line.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: host key persistence

The base spec §"Runtime, config, and concurrency": an ed25519 host key generated
once on first `serve`, stored at `~/.config/patvault/relay_host_ed25519` (mode
0600) and **reused across restarts so the guest's `known_hosts` pin stays
valid**. Its fingerprint is printed on generation so the operator can pin it.

**Files:**
- Create: `internal/relay/server.go`
- Test: `internal/relay/server_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  func loadOrCreateHostKey(path string) (signer ssh.Signer, created bool, err error)
  ```
  `created` reports whether this call generated the key, so the caller knows when
  to print the fingerprint.

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/server_test.go`:

```go
package relay

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The guest pins the host key in known_hosts, so a key that changed across
// restarts would look exactly like an impersonation attempt and break every
// clone. This is the property that matters most about the file.
func TestLoadOrCreateHostKeyIsStableAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")

	first, created, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("first loadOrCreateHostKey: %v", err)
	}
	if !created {
		t.Error("created = false on first call, want true")
	}

	second, created, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateHostKey: %v", err)
	}
	if created {
		t.Error("created = true on second call, want false — the key must be reused")
	}

	wantFP := ssh.FingerprintSHA256(first.PublicKey())
	gotFP := ssh.FingerprintSHA256(second.PublicKey())
	if gotFP != wantFP {
		t.Errorf("fingerprint changed across restarts: %s then %s", wantFP, gotFP)
	}
}

func TestLoadOrCreateHostKeyIsEd25519(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	signer, _, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	if got := signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", got, ssh.KeyAlgoED25519)
	}
}

func TestLoadOrCreateHostKeyIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	if _, _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestLoadOrCreateHostKeyCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config", "relay_host_ed25519")
	if _, _, err := loadOrCreateHostKey(path); err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("host key not created: %v", err)
	}
}

// A corrupt key file must be reported, never silently replaced: regenerating it
// would break the guest's known_hosts pin without saying so.
func TestLoadOrCreateHostKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay_host_ed25519")
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := loadOrCreateHostKey(path); err == nil {
		t.Fatal("loadOrCreateHostKey = nil error, want error on a corrupt key file")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: loadOrCreateHostKey`.

- [ ] **Step 3: Write the implementation**

Create `internal/relay/server.go`:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/server.go internal/relay/server_test.go
git commit -m "$(cat <<'EOF'
feat: persist the relay's ed25519 host key across restarts

Generated once on first serve, stored 0600, reused thereafter. The guest pins
this key in known_hosts, so stability is the whole point: a key that rotated on
restart is indistinguishable from an impersonation attempt and breaks every
clone until the operator re-pins.

That is also why a corrupt key file is an error rather than a reason to
regenerate -- silently minting a new identity is the one behavior the pin exists
to catch.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `Request`, the `bridge` seam, and repo resolution

This task builds the **fail-before-first-byte** half that needs no upstream:
resolve the repo to a stored PAT, check expiry, decrypt. Per the design's §"The
seam", by the time a `Request` exists "every fallible check (auth, exec parse, v2
gate, repo resolution, expiry, decrypt) has already passed".

The expiry check runs **before** decrypt and before any upstream contact — that
is what makes the expired-token refusal free of a network round trip (base spec
§"Expiry as a feature").

**Files:**
- Modify: `internal/relay/server.go`
- Test: `internal/relay/server_test.go`

**Interfaces:**
- Consumes: `errNoPAT`, `errExpiredPAT`, `upstreamHost` (Task 1); `internal/db`;
  `internal/encrypt`.
- Produces:
  ```go
  type Request struct {
      Repo string // normalized "owner/repo", already shape-checked
      PAT  string // decrypted, already expiry-checked
  }

  type bridge interface {
      Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error
      Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
  }

  type Server struct {
      HostKeyPath  string
      AuthKeysPath string
      OpenDB       func() (*db.DB, error)
      Keyring      encrypt.Keyring
      Bridge       bridge
      Logger       *slog.Logger
  }

  func (s *Server) resolve(repo string) (Request, error)
  ```
  `resolve` returns a `*relayError` for a missing or expired PAT, and a plain
  wrapped error for a host-side fault (Task 6 maps that to `errInternal`).

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/server_test.go` — and add these imports to its import
block: `"errors"`, `"strings"`, `"time"`,
`"github.com/quells-bot/patvault/internal/db"`,
`"github.com/quells-bot/patvault/internal/encrypt"`.

```go
// newStore returns an OpenDB func and a keyring backed by a temp dir. The
// FileKeyring bootstraps its own master key on first use, so these tests never
// touch the OS keychain.
func newStore(t *testing.T) (func() (*db.DB, error), encrypt.Keyring) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "credentials.db")
	kr := encrypt.FileKeyring{Path: filepath.Join(dir, "master.key")}
	open := func() (*db.DB, error) { return db.Open(dbPath) }
	return open, kr
}

// storePAT encrypts pat and stores it for repo, exactly as 'patvault add' would.
// expires is a unix timestamp, or nil for a token that never expires.
func storePAT(t *testing.T, open func() (*db.DB, error), kr encrypt.Keyring, repo, pat string, expires *int64) {
	t.Helper()
	d, err := open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	mk, err := encrypt.GetOrCreateMasterKey(kr)
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	key, err := encrypt.DeriveKey(mk, upstreamHost, repo)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	blob, err := encrypt.Encrypt(key, []byte(pat))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := d.Upsert(db.Credential{
		Host: upstreamHost, Path: repo, Username: "x-access-token",
		PAT: blob, Label: upstreamHost + "/" + repo,
		Created: time.Now().Unix(), Expires: expires,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

func TestResolveDecryptsStoredPAT(t *testing.T) {
	open, kr := newStore(t)
	storePAT(t, open, kr, "owner/repo", "ghp_secret_value", nil)
	s := &Server{OpenDB: open, Keyring: kr}

	req, err := s.resolve("owner/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if req.Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", req.Repo, "owner/repo")
	}
	if req.PAT != "ghp_secret_value" {
		t.Errorf("PAT = %q, want the decrypted token", req.PAT)
	}
}

func TestResolveAcceptsUnexpiredPAT(t *testing.T) {
	open, kr := newStore(t)
	future := time.Now().Add(24 * time.Hour).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_live", &future)
	s := &Server{OpenDB: open, Keyring: kr}

	req, err := s.resolve("owner/repo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if req.PAT != "ghp_live" {
		t.Errorf("PAT = %q, want %q", req.PAT, "ghp_live")
	}
}

func TestResolveRefusesMissingPAT(t *testing.T) {
	open, kr := newStore(t)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/never-added")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v (%T), want a *relayError", err, err)
	}
	if want := errNoPAT("owner/never-added").Error(); re.Error() != want {
		t.Errorf("message =\n%q\nwant\n%q", re.Error(), want)
	}
	if re.Exit() != 1 {
		t.Errorf("exit = %d, want 1", re.Exit())
	}
}

func TestResolveRefusesExpiredPAT(t *testing.T) {
	open, kr := newStore(t)
	past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_stale", &past)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/repo")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v (%T), want a *relayError", err, err)
	}
	want := "patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then"
	if re.Error() != want {
		t.Errorf("message =\n%q\nwant\n%q", re.Error(), want)
	}
}

// The refusal must not leak the token it refused to use.
func TestResolveExpiredMessageDoesNotLeakPAT(t *testing.T) {
	open, kr := newStore(t)
	past := time.Now().Add(-time.Hour).Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_super_secret", &past)
	s := &Server{OpenDB: open, Keyring: kr}

	_, err := s.resolve("owner/repo")
	if err == nil {
		t.Fatal("resolve = nil error, want a refusal")
	}
	if strings.Contains(err.Error(), "ghp_super_secret") {
		t.Errorf("refusal leaked the PAT: %v", err)
	}
}

// A token expiring exactly now is expired: the spec's check is "<= now".
func TestResolveTreatsExpiryBoundaryAsExpired(t *testing.T) {
	open, kr := newStore(t)
	now := time.Now().Unix()
	storePAT(t, open, kr, "owner/repo", "ghp_boundary", &now)
	s := &Server{OpenDB: open, Keyring: kr}

	if _, err := s.resolve("owner/repo"); err == nil {
		t.Fatal("resolve = nil error, want a refusal for a token expiring now")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: Server`, `undefined: Request`.

- [ ] **Step 3: Write the implementation**

Add to `internal/relay/server.go` — its import block becomes:

```go
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
```

and append:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/server.go internal/relay/server_test.go
git commit -m "$(cat <<'EOF'
feat: resolve a repo to a decrypted PAT, refusing before any upstream

Repo resolution, the expiry check, and the decrypt -- the half of
fail-before-first-byte that needs no upstream at all. Reuses the credential
helper's keyring -> derive -> decrypt chain rather than growing a second one.

Expiry is checked before the decrypt and before any network contact, which is
what makes the design's "expiry as a feature" free: a lapsed token costs no round
trip to refuse.

Also names the seam slice 3 implements, before slice 2 ships, so this slice
cannot grow a shape slice 3 cannot use. The bridge takes io.Reader/io.Writer
rather than an ssh.Channel, so it never sees SSH and its tests will not need one.
Request exists only once every fallible check has passed.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `Serve` — the front door that refuses every exec

The listener, allowlist auth, the accept loop, concurrency, graceful shutdown,
and the session request loop. **This task's `dispatch` refuses every exec** with
the disallowed-exec row; Task 6 gives it a brain. That ordering is deliberate:
"the SSH front door that refuses everything" is a coherent, testable deliverable,
and both of this task's exec tests (a shell request, and `git-upload-archive`)
stay true once Task 6 lands.

**Exit codes are asserted here, through an in-process `x/crypto/ssh` client** —
see §"What is pinned" for why they cannot be asserted through real `git`.

**Files:**
- Modify: `internal/relay/server.go`
- Test: `internal/relay/server_test.go`

**Interfaces:**
- Consumes: `loadOrCreateHostKey` (Task 3), `loadAuthorizedKeys` (Task 2),
  `errDisallowedExec` (Task 1), `Server` (Task 4).
- Produces:
  ```go
  func (s *Server) Serve(ctx context.Context, ln net.Listener) error
  func (s *Server) dispatch(ctx context.Context, ch ssh.Channel, fp, cmd, gitProtocol string)
  ```
  `Serve` takes the listener rather than an address so tests can bind
  `127.0.0.1:0` and learn the port; `commands/relay.go` does the `net.Listen`.
  `Serve` returns nil after a graceful shutdown.

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/server_test.go` — add `"bytes"`, `"context"`,
`"crypto/ed25519"`, `"crypto/rand"`, `"io"`, `"net"`, and `"sync"` to its import
block.

```go
// newSigner returns a fresh ed25519 signer and its authorized_keys line.
func newSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

// newTestServer builds a Server whose host key and allowlist live under
// t.TempDir, with allowed listed in the allowlist and an empty credential store.
func newTestServer(t *testing.T, allowedLine string) *Server {
	t.Helper()
	dir := t.TempDir()
	authKeys := filepath.Join(dir, "relay_authorized_keys")
	if err := os.WriteFile(authKeys, []byte(allowedLine), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	open, kr := newStore(t)
	return &Server{
		HostKeyPath:  filepath.Join(dir, "relay_host_ed25519"),
		AuthKeysPath: authKeys,
		OpenDB:       open,
		Keyring:      kr,
	}
}

// startRelay serves s on 127.0.0.1:0 and returns its address, shutting the
// server down when the test ends. A Serve that does not return on cancel fails
// the test: graceful shutdown is a requirement, not a nicety.
func startRelay(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v, want nil after a graceful shutdown", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return within 10s of cancellation")
		}
	})
	return ln.Addr().String()
}

// runExec runs one exec against the relay and returns the session's stderr and
// exit status.
//
// This is the precise instrument for exit codes: raw ssh propagates the relay's
// exit-status verbatim, whereas real git rewrites every remote refusal to its own
// 128 (see the plan's §"What is pinned"). The real-git gate asserts the message,
// not the code.
func runExec(t *testing.T, addr string, signer ssh.Signer, env map[string]string, cmd string) (stderr string, exit int) {
	t.Helper()
	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	for k, v := range env {
		if err := sess.Setenv(k, v); err != nil {
			t.Fatalf("setenv %s: %v", k, err)
		}
	}
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf

	switch err := sess.Run(cmd).(type) {
	case nil:
		return errBuf.String(), 0
	case *ssh.ExitError:
		return errBuf.String(), err.ExitStatus()
	default:
		t.Fatalf("run %q: %v", cmd, err)
		return "", 0
	}
}

func TestServeRejectsUnlistedKey(t *testing.T) {
	_, allowedLine := newSigner(t)
	intruder, _ := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(intruder)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		t.Fatal("dial with an unlisted key succeeded, want an auth failure")
	}
}

func TestServeAcceptsListedKey(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial with a listed key: %v", err)
	}
	cc.Close()
}

// The relay presents the key it persisted, so a guest that pinned it stays
// pinned across restarts.
func TestServePresentsThePersistedHostKey(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)

	want, _, err := loadOrCreateHostKey(s.HostKeyPath)
	if err != nil {
		t.Fatalf("loadOrCreateHostKey: %v", err)
	}
	addr := startRelay(t, s)

	var got ssh.PublicKey
	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return nil
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	if gotFP, wantFP := ssh.FingerprintSHA256(got), ssh.FingerprintSHA256(want.PublicKey()); gotFP != wantFP {
		t.Errorf("host key = %s, want the persisted %s", gotFP, wantFP)
	}
}

// A relay serves git and nothing else: a shell (and, by the same default branch,
// a pty-req or a subsystem) is the disallowed-exec row, not a request to
// negotiate.
func TestServeRefusesShell(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	// A pipe, not a Buffer: Shell() returns the moment the request is refused,
	// which races the relay's stderr write. Reading the pipe to EOF waits for
	// the relay to write the refusal and close the channel, so this is
	// deterministic. (runExec can use a Buffer because Session.Run waits for the
	// exit-status and the output copies.)
	stderr, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := sess.Shell(); err == nil {
		t.Error("Shell() = nil error, want a refusal")
	}
	msg, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if want := "patvault: only git fetch/push are permitted"; !strings.Contains(string(msg), want) {
		t.Errorf("stderr = %q, want it to contain %q", msg, want)
	}
}

// git-upload-archive would expose 'git archive --remote'. It is refused in this
// task because every exec is, and stays refused once Task 6 parses it.
func TestServeRefusesUploadArchive(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	stderr, exit := runExec(t, addr, signer, nil, `git-upload-archive '/owner/repo.git'`)
	if want := "patvault: only git fetch/push are permitted"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if exit != 128 {
		t.Errorf("exit = %d, want 128", exit)
	}
}

// Errors go to stderr, never stdout: git parses stdout as pkt-lines, and text
// injected there corrupts the parse.
func TestServeWritesRefusalToStderrNotStdout(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	_ = sess.Run(`git-upload-archive '/owner/repo.git'`)

	if outBuf.Len() != 0 {
		t.Errorf("stdout = %q, want no bytes — text on stdout corrupts git's pkt-line parse", outBuf.String())
	}
	if errBuf.Len() == 0 {
		t.Error("stderr is empty, want the refusal")
	}
}

// A goroutine per connection, per the base spec's concurrency note.
func TestServeHandlesConcurrentConnections(t *testing.T) {
	signer, allowedLine := newSigner(t)
	addr := startRelay(t, newTestServer(t, allowedLine))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stderr, exit := runExec(t, addr, signer, nil, `git-upload-archive '/owner/repo.git'`)
			if exit != 128 {
				t.Errorf("exit = %d, want 128", exit)
			}
			if !strings.Contains(stderr, "patvault:") {
				t.Errorf("stderr = %q, want a patvault refusal", stderr)
			}
		}()
	}
	wg.Wait()
}

func TestServeFailsOnMissingAllowlist(t *testing.T) {
	dir := t.TempDir()
	open, kr := newStore(t)
	s := &Server{
		HostKeyPath:  filepath.Join(dir, "relay_host_ed25519"),
		AuthKeysPath: filepath.Join(dir, "does-not-exist"),
		OpenDB:       open,
		Keyring:      kr,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if err := s.Serve(context.Background(), ln); err == nil {
		t.Fatal("Serve = nil error, want a startup error for a missing allowlist")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `s.Serve undefined`.

- [ ] **Step 3: Write the implementation**

Add `"net"` and `"sync"` to `server.go`'s import block, then append:

```go
// SSH channel-request payloads. These mirror RFC 4254 and are the shape
// spike/relay-ssh/sshreq.go pinned against a real client.
type (
	envRequest  struct{ Name, Value string }
	execRequest struct{ Command string }
	exitStatus  struct{ Status uint32 }
)

// Serve accepts connections on ln until ctx is cancelled, then stops accepting
// and waits for in-flight sessions to drain. It returns nil after a graceful
// shutdown.
//
// It takes a listener rather than an address so the caller owns the bind — which
// is what lets commands/relay.go refuse a wildcard address and tests bind
// 127.0.0.1:0.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hostKey, created, err := loadOrCreateHostKey(s.HostKeyPath)
	if err != nil {
		return err
	}
	if created {
		s.logger().Info("generated relay host key",
			"path", s.HostKeyPath,
			"fingerprint", ssh.FingerprintSHA256(hostKey.PublicKey()))
	}
	keys, err := loadAuthorizedKeys(s.AuthKeysPath)
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			if !keys.has(key) {
				s.logger().Info("refused unlisted key", "fingerprint", fp)
				return nil, fmt.Errorf("key %s is not authorized", fp)
			}
			// The fingerprint rides along so the session can log which agent it
			// served without re-deriving it.
			return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	// Cancellation unblocks Accept by closing the listener.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn, cfg)
		}()
	}
}

// handleConn runs one SSH connection: handshake, then its session channels.
func (s *Server) handleConn(ctx context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()

	sConn, chans, globalReqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		// An unlisted key lands here; PublicKeyCallback already logged it.
		s.logger().Debug("handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(globalReqs)

	fp := sConn.Permissions.Extensions["fingerprint"]
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		s.handleSession(ctx, newCh, fp)
	}
}

// handleSession runs one session channel's request loop: env requests are
// captured, the exec is dispatched, and everything else is refused.
//
// The shape is spike/relay-ssh's serveOnce, which the findings note names as the
// reference for exactly this loop.
func (s *Server) handleSession(ctx context.Context, newCh ssh.NewChannel, fp string) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	// GIT_PROTOCOL arrives as an env request before the exec (relay-ssh spike),
	// so the version is known by the time the exec is handled. Never count env
	// requests: the caller's locale is forwarded through them too, so the count
	// varies with the invoking shell.
	var gitProtocol string

	for req := range reqs {
		switch req.Type {
		case "env":
			var e envRequest
			if err := ssh.Unmarshal(req.Payload, &e); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("env payload: %w", err))
				return
			}
			if e.Name == "GIT_PROTOCOL" {
				gitProtocol = e.Value
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "exec":
			var x execRequest
			if err := ssh.Unmarshal(req.Payload, &x); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("exec payload: %w", err))
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
			s.dispatch(ctx, ch, fp, x.Command, gitProtocol)
			return

		default:
			// shell, pty-req, subsystem, ... — a relay serves git and nothing
			// else, so these are the disallowed-exec row rather than a
			// negotiation.
			if req.WantReply {
				req.Reply(false, nil)
			}
			s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("channel request %q", req.Type))
			return
		}
	}
}

// dispatch turns one exec into an outcome.
//
// TASK 6 REPLACES THIS BODY. Until then the front door refuses everything, which
// is this slice's whole point: a large share of the error table is testable with
// no upstream in existence.
func (s *Server) dispatch(ctx context.Context, ch ssh.Channel, fp, cmd, gitProtocol string) {
	s.refuse(ch, fp, "", "", errDisallowedExec(), fmt.Errorf("exec %q: no dispatch yet", cmd))
}

// refuse writes err's message to the channel's stderr and closes with its exit
// status, then records the outcome host-side.
//
// Errors never touch stdout: git parses stdout as pkt-lines, so text injected
// there corrupts the parse. Over SSH git passes remote stderr straight to the
// user's terminal, which is why a patvault:-prefixed line is readable there.
func (s *Server) refuse(ch ssh.Channel, fp, op, repo string, clientErr *relayError, cause error) {
	fmt.Fprintln(ch.Stderr(), clientErr.Error())
	ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: clientErr.Exit()}))

	// The operational log records the agent, the operation, and why — never the
	// PAT.
	s.logger().Info("refused",
		"fingerprint", fp,
		"op", op,
		"repo", repo,
		"exit", clientErr.Exit(),
		"retryable", clientErr.Retryable(),
		"cause", cause)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Then confirm the whole suite is still green, with the race detector — this is the
first concurrent code in the package:

Run: `go test -race -count=1 ./...`
Expected: PASS for every package.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/server.go internal/relay/server_test.go
git commit -m "$(cat <<'EOF'
feat: the SSH front door -- host key, allowlist auth, session loop

Serve takes a listener rather than an address so the caller owns the bind: that
is what will let the command refuse a wildcard address and lets tests bind
127.0.0.1:0 and learn the port.

dispatch refuses every exec for now. That is the slice's point rather than a
placeholder -- a shell, a pty, and git-upload-archive are all refusable with no
upstream in existence, and those tests stay true once dispatch grows a brain.

The request loop follows spike/relay-ssh's serveOnce, which the findings note
names as the reference for it. Two things it takes from that spike: GIT_PROTOCOL
is captured from an env request before the exec, and the env requests are never
counted -- the caller's locale rides through them too, so the count is a property
of the invoking shell, not of git.

Refusals go to stderr and never stdout, since text on stdout corrupts git's
pkt-line parse.

Exit codes are asserted through an in-process ssh client, not through git: git
rewrites every remote refusal to its own 128 and discards what the relay sent, so
asserting them through git would pass for the wrong reason.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: exec dispatch — parse, gate on v2, resolve

Now `dispatch` earns its name: `parseExec` (slice 1) → the v2 gate → `resolve`
(Task 4) → the `bridge` seam.

**The v2 gate compares the value.** `GIT_PROTOCOL == "version=2"`. A presence
check fails open, because git sends `GIT_PROTOCOL=version=1` under
`protocol.version=1` — the relay-ssh findings note records this as a mistake
already made once. The gate applies to **fetch only**: `git-receive-pack` has no
v2 and pushes bridge cleanly regardless.

**Files:**
- Modify: `internal/relay/server.go`
- Test: `internal/relay/server_test.go`

**Interfaces:**
- Consumes: `parseExec`, `opFetch`, `opPush` (slice 1); `resolve` (Task 4);
  `errNotV2`, `errDisallowedExec`, `errInternal` (Task 1).
- Produces:
  ```go
  const gitProtocolV2 = "version=2"
  func clientError(err error) *relayError
  ```
  `dispatch`'s signature is unchanged from Task 5.

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/server_test.go` — add `"fmt"` to its import block
(`TestClientErrorPassesRelayErrorsThrough` wraps an error with it).

```go
// fakeBridge records what dispatch handed it. In this slice its main job is to
// fail the test when it is called at all: every refusal below must happen before
// anything upstream would be contacted.
type fakeBridge struct {
	mu      sync.Mutex
	fetched []Request
	pushed  []Request
	err     error
}

func (b *fakeBridge) Fetch(_ context.Context, req Request, _ io.Reader, out io.Writer) error {
	b.mu.Lock()
	b.fetched = append(b.fetched, req)
	b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	_, _ = out.Write([]byte("0008fetch"))
	return nil
}

func (b *fakeBridge) Push(_ context.Context, req Request, _ io.Reader, out io.Writer) error {
	b.mu.Lock()
	b.pushed = append(b.pushed, req)
	b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	_, _ = out.Write([]byte("0007push"))
	return nil
}

func (b *fakeBridge) calls() (fetched, pushed []Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Request(nil), b.fetched...), append([]Request(nil), b.pushed...)
}

// v2Env is what a real git sends before a fetch exec under protocol.version=2.
var v2Env = map[string]string{"GIT_PROTOCOL": "version=2"}

// The decisive gate test. Git announces version=1 under protocol.version=1, so a
// presence-only check would admit a v1 client into the v2 stateless pump. Each
// case here is a value a real git was observed to send (relay-ssh spike).
func TestDispatchV2GateComparesValue(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"v2 passes the gate", map[string]string{"GIT_PROTOCOL": "version=2"}, false},
		{"v1 is refused, not admitted", map[string]string{"GIT_PROTOCOL": "version=1"}, true},
		{"v0 sends nothing and is refused", nil, true},
		{"empty value is refused", map[string]string{"GIT_PROTOCOL": ""}, true},
		{"a value merely containing version=2 is refused", map[string]string{"GIT_PROTOCOL": "version=2x"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, allowedLine := newSigner(t)
			s := newTestServer(t, allowedLine)
			fb := &fakeBridge{}
			s.Bridge = fb
			storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
			addr := startRelay(t, s)

			stderr, exit := runExec(t, addr, signer, tc.env, `git-upload-pack '/owner/repo.git'`)
			fetched, _ := fb.calls()

			if !tc.wantErr {
				if len(fetched) != 1 {
					t.Fatalf("bridge fetched %d times, want 1; stderr=%q", len(fetched), stderr)
				}
				if exit != 0 {
					t.Errorf("exit = %d, want 0", exit)
				}
				return
			}
			want := "patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)"
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, want)
			}
			if exit != 1 {
				t.Errorf("exit = %d, want 1", exit)
			}
			if len(fetched) != 0 {
				t.Errorf("bridge was called %d times for a refused fetch, want 0", len(fetched))
			}
		})
	}
}

// Push has no v2, so the gate must not apply to it: git sends no GIT_PROTOCOL
// before a receive-pack exec (relay-ssh spike).
func TestDispatchPushNeedsNoV2(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	fb := &fakeBridge{}
	s.Bridge = fb
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
	addr := startRelay(t, s)

	_, exit := runExec(t, addr, signer, nil, `git-receive-pack '/owner/repo.git'`)
	_, pushed := fb.calls()

	if len(pushed) != 1 {
		t.Fatalf("bridge pushed %d times, want 1", len(pushed))
	}
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
}

// The bridge receives a fully-resolved Request: the normalized repo and the
// decrypted PAT, with every check already passed.
func TestDispatchHandsBridgeAResolvedRequest(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	fb := &fakeBridge{}
	s.Bridge = fb
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_the_token", nil)
	addr := startRelay(t, s)

	// The .git suffix and leading slash are the user's URL's, and normalize away.
	if _, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`); exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	fetched, _ := fb.calls()
	if len(fetched) != 1 {
		t.Fatalf("bridge fetched %d times, want 1", len(fetched))
	}
	if fetched[0].Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", fetched[0].Repo, "owner/repo")
	}
	if fetched[0].PAT != "ghp_the_token" {
		t.Errorf("PAT = %q, want the decrypted token", fetched[0].PAT)
	}
}

// Every refusal below must happen before the bridge is reached: this is the
// no-upstream-contacted half of fail-before-first-byte, and it is exactly what
// makes this slice testable without an upstream.
func TestDispatchRefusesBeforeReachingTheBridge(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		cmd      string
		wantMsg  string
		wantExit int
		setup    func(t *testing.T, s *Server)
	}{
		{
			name:     "no stored PAT",
			env:      v2Env,
			cmd:      `git-upload-pack '/owner/never-added.git'`,
			wantMsg:  "patvault: no token stored for github.com/owner/never-added; run 'patvault add' on the host — this will not succeed until then",
			wantExit: 1,
		},
		{
			name: "expired PAT",
			env:  v2Env,
			cmd:  `git-upload-pack '/owner/stale.git'`,
			setup: func(t *testing.T, s *Server) {
				past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
				storePAT(t, s.OpenDB, s.Keyring, "owner/stale", "ghp_stale", &past)
			},
			wantMsg:  "patvault: token for github.com/owner/stale expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then",
			wantExit: 1,
		},
		{
			name:     "fetch without v2",
			cmd:      `git-upload-pack '/owner/repo.git'`,
			wantMsg:  "patvault: relay requires git wire protocol v2",
			wantExit: 1,
		},
		{
			name:     "upload-archive",
			env:      v2Env,
			cmd:      `git-upload-archive '/owner/repo.git'`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
		{
			name:     "unknown command",
			env:      v2Env,
			cmd:      `bash -c id`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
		{
			name:     "path traversal",
			env:      v2Env,
			cmd:      `git-upload-pack '/owner/../../etc/passwd'`,
			wantMsg:  "patvault: only git fetch/push are permitted",
			wantExit: 128,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, allowedLine := newSigner(t)
			s := newTestServer(t, allowedLine)
			fb := &fakeBridge{}
			s.Bridge = fb
			storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
			if tc.setup != nil {
				tc.setup(t, s)
			}
			addr := startRelay(t, s)

			stderr, exit := runExec(t, addr, signer, tc.env, tc.cmd)
			if !strings.Contains(stderr, tc.wantMsg) {
				t.Errorf("stderr =\n%q\nwant it to contain\n%q", stderr, tc.wantMsg)
			}
			if exit != tc.wantExit {
				t.Errorf("exit = %d, want %d", exit, tc.wantExit)
			}
			fetched, pushed := fb.calls()
			if len(fetched) != 0 || len(pushed) != 0 {
				t.Errorf("bridge was reached (%d fetch, %d push) for a refusal that precedes it",
					len(fetched), len(pushed))
			}
		})
	}
}

// A nil Bridge is slice 2's normal state. It must refuse rather than panic.
func TestDispatchWithNoBridgeRefuses(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine) // Bridge left nil
	storePAT(t, s.OpenDB, s.Keyring, "owner/repo", "ghp_live", nil)
	addr := startRelay(t, s)

	stderr, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`)
	if !strings.Contains(stderr, "patvault: relay failed internally") {
		t.Errorf("stderr = %q, want the internal-fault message", stderr)
	}
	if exit != 1 {
		t.Errorf("exit = %d, want 1", exit)
	}
}

// A host-side fault must not hand the client a message it cannot act on, and
// must not leak the fault's detail.
func TestDispatchMapsHostFaultToInternalError(t *testing.T) {
	signer, allowedLine := newSigner(t)
	s := newTestServer(t, allowedLine)
	s.Bridge = &fakeBridge{}
	s.OpenDB = func() (*db.DB, error) { return nil, errors.New("disk on fire") }
	addr := startRelay(t, s)

	stderr, exit := runExec(t, addr, signer, v2Env, `git-upload-pack '/owner/repo.git'`)
	if !strings.Contains(stderr, "patvault: relay failed internally") {
		t.Errorf("stderr = %q, want the internal-fault message", stderr)
	}
	if strings.Contains(stderr, "disk on fire") {
		t.Errorf("stderr leaked the host-side cause: %q", stderr)
	}
	if exit != 1 {
		t.Errorf("exit = %d, want 1", exit)
	}
}

func TestClientErrorPassesRelayErrorsThrough(t *testing.T) {
	re := errNotV2()
	if got := clientError(re); got != re {
		t.Errorf("clientError(relayError) = %v, want the same error back", got)
	}
	if got := clientError(fmt.Errorf("wrapped: %w", re)); got != re {
		t.Errorf("clientError(wrapped relayError) = %v, want the unwrapped row", got)
	}
	if got := clientError(errors.New("db exploded")); got.Error() != errInternal().Error() {
		t.Errorf("clientError(plain error) = %q, want the internal-fault message", got.Error())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: clientError`, and the dispatch tests failing
because Task 5's `dispatch` refuses everything.

- [ ] **Step 3: Write the implementation**

In `internal/relay/server.go`, **replace the Task 5 `dispatch` stub entirely**
with the following, and append `clientError` and `gitProtocolV2`:

```go
// gitProtocolV2 is the exact GIT_PROTOCOL value that admits a fetch.
//
// The comparison is against the value, never the presence of the env request: a
// real git sends GIT_PROTOCOL=version=1 under protocol.version=1, so a presence
// check admits a v1 client into the v2 stateless pump. The relay-ssh findings
// note records this being got wrong once already.
const gitProtocolV2 = "version=2"

// dispatch turns one exec into an outcome: parse it, gate it on v2, resolve the
// repo to a decrypted PAT, and only then hand the bridge a Request.
//
// Every refusal here happens before the bridge is reached, and therefore before
// any upstream contact — the no-network half of the fail-before-first-byte
// invariant. The other half (the advertisement must return 2xx before a byte
// reaches out) is the bridge's, in slice 3.
func (s *Server) dispatch(ctx context.Context, ch ssh.Channel, fp, cmd, gitProtocol string) {
	op, repo, err := parseExec(cmd)
	if err != nil {
		s.refuse(ch, fp, "", "", errDisallowedExec(), err)
		return
	}

	// Push has no v2 and bridges cleanly regardless, so the gate is fetch-only.
	if op == opFetch && gitProtocol != gitProtocolV2 {
		s.refuse(ch, fp, op, repo, errNotV2(),
			fmt.Errorf("GIT_PROTOCOL = %q, want %q", gitProtocol, gitProtocolV2))
		return
	}

	req, err := s.resolve(repo)
	if err != nil {
		s.refuse(ch, fp, op, repo, clientError(err), err)
		return
	}
	if s.Bridge == nil {
		s.refuse(ch, fp, op, repo, errInternal(), errors.New("no bridge configured"))
		return
	}

	switch op {
	case opFetch:
		err = s.Bridge.Fetch(ctx, req, ch, ch)
	case opPush:
		err = s.Bridge.Push(ctx, req, ch, ch)
	}
	if err != nil {
		// Streaming may already have started, in which case this cannot be
		// clean: the client gets the message and a non-zero status, and the host
		// log gets the detail.
		s.refuse(ch, fp, op, repo, clientError(err), err)
		return
	}

	ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 0}))
	s.logger().Info("served", "fingerprint", fp, "op", op, "repo", repo)
}

// clientError maps an internal failure to what the client is told. A relayError
// is already a row of the spec's table and passes through; anything else is a
// host-side fault the client can do nothing about, so it becomes the internal
// row and the real cause goes to the log.
func clientError(err error) *relayError {
	var re *relayError
	if errors.As(err, &re) {
		return re
	}
	return errInternal()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Run: `go test -race -count=1 ./...`
Expected: PASS for every package.

Run: `go vet ./internal/relay/...` and `gofmt -l internal/relay`
Expected: no output from either.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/server.go internal/relay/server_test.go
git commit -m "$(cat <<'EOF'
feat: exec dispatch -- parse, gate on v2, resolve, hand off

dispatch now earns its name: parseExec, then the v2 gate, then repo resolution,
and only then a Request for the bridge. Everything it refuses, it refuses before
the bridge is reached and therefore before any upstream contact -- the no-network
half of fail-before-first-byte. The other half, the 2xx advertisement, is the
bridge's in slice 3.

The v2 gate compares GIT_PROTOCOL's value rather than its presence, and the test
drives every value a real git was observed to send: v0 sends nothing, v1 sends
version=1. A presence check admits that v1 client into the v2 stateless pump,
which the relay-ssh note records as a mistake this project already made once. The
gate is fetch-only, since receive-pack has no v2.

A host-side fault -- unreadable db, locked keychain, bad decrypt -- becomes the
internal row rather than reaching the client, whose only useful information is
that retrying will not help. The cause goes to the log.

A nil Bridge stays slice 2's normal state and refuses rather than panics.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `commands/relay.go` — the cobra wiring

Base spec §"Command surface":

```
patvault relay serve   [--listen <ip:port>] [--authorized-keys <path>] [--host-key <path>]
patvault relay add-key <path-to-pubkey>
```

**`--listen` is required and must be an explicit IP:port.** The spec forbids
auto-detecting the host-only interface and forbids binding `0.0.0.0`:
auto-detection "risks binding wider than intended for a security boundary".

**Files:**
- Create: `internal/commands/relay.go`
- Test: `internal/commands/relay_test.go`
- Modify: `cmd/patvault/main.go`

**Interfaces:**
- Consumes: `relay.Server`, `relay.NewRelayCmd`'s dependencies.
- Produces:
  ```go
  func NewRelayCmd(openDB func() (*db.DB, error), kr encrypt.Keyring, defaultHostKey, defaultAuthKeys string) *cobra.Command
  func validateListen(addr string) error
  ```

The relay package needs one more exported helper for `add-key`. Add it to
`internal/relay/authkeys.go`:

```go
// AddKey appends the public key in pubkeyFile to the allowlist at
// allowlistPath, reporting whether it was new. It is the exported face of
// appendAuthorizedKey for 'patvault relay add-key'.
func AddKey(allowlistPath, pubkeyFile string) (added bool, err error) {
	return appendAuthorizedKey(allowlistPath, pubkeyFile)
}
```

- [ ] **Step 1: Write the failing tests**

Create `internal/commands/relay_test.go`:

```go
package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Binding a credential-injecting relay wider than the host-only interface is the
// one configuration mistake with a security consequence, so it is refused rather
// than guessed at.
func TestValidateListen(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"host-only interface", "192.168.64.1:2222", false},
		{"loopback", "127.0.0.1:2222", false},
		{"ipv6 loopback", "[::1]:2222", false},
		{"empty is a startup error", "", true},
		{"wildcard v4", "0.0.0.0:2222", true},
		{"wildcard v6", "[::]:2222", true},
		{"bare port means every interface", ":2222", true},
		{"no port", "192.168.64.1", true},
		{"hostname, not an IP", "localhost:2222", true},
		{"garbage", "not-an-address", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListen(tc.addr)
			if tc.wantErr && err == nil {
				t.Errorf("validateListen(%q) = nil, want an error", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateListen(%q) = %v, want nil", tc.addr, err)
			}
		})
	}
}

func newPubKeyFile(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	path := filepath.Join(dir, "agent.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return path
}

func TestRelayAddKeyAppendsAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	pubFile := newPubKeyFile(t, dir)
	allowlist := filepath.Join(dir, "relay_authorized_keys")

	run := func() string {
		cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), allowlist)
		var out strings.Builder
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"add-key", pubFile})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("add-key: %v", err)
		}
		return out.String()
	}

	if got := run(); !strings.Contains(got, "added") {
		t.Errorf("first add-key said %q, want it to report the key was added", got)
	}
	if got := run(); !strings.Contains(got, "already") {
		t.Errorf("second add-key said %q, want it to report a no-op", got)
	}

	data, err := os.ReadFile(allowlist)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	if n := len(strings.Fields(strings.TrimSpace(string(data)))); n != 2 {
		t.Errorf("allowlist = %q, want exactly one key line (type + base64)", data)
	}
}

func TestRelayAddKeyRejectsNonKey(t *testing.T) {
	dir := t.TempDir()
	notAKey := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notAKey, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"add-key", notAKey})
	if err := cmd.Execute(); err == nil {
		t.Fatal("add-key on a non-key file = nil error, want an error")
	}
}

func TestRelayServeRequiresListen(t *testing.T) {
	dir := t.TempDir()
	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"serve"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("serve without --listen = nil error, want a startup error")
	}
}

func TestRelayServeRejectsWildcardListen(t *testing.T) {
	dir := t.TempDir()
	cmd := NewRelayCmd(nil, nil, filepath.Join(dir, "host_key"), filepath.Join(dir, "allowlist"))
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"serve", "--listen", "0.0.0.0:2222"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("serve --listen 0.0.0.0:2222 = nil error, want a refusal")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/commands/...`
Expected: FAIL with `undefined: NewRelayCmd`, `undefined: validateListen`.

- [ ] **Step 3: Write the implementation**

Create `internal/commands/relay.go`:

```go
package commands

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/relay"
)

// NewRelayCmd builds 'patvault relay', the credential-injecting transport relay.
func NewRelayCmd(openDB func() (*db.DB, error), kr encrypt.Keyring, defaultHostKey, defaultAuthKeys string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "credential-injecting git transport relay",
		Long: "Serve the agent's git over SSH and bridge it to GitHub over HTTPS,\n" +
			"injecting a stored PAT upstream. The agent never holds the token.",
	}
	cmd.AddCommand(newRelayServeCmd(openDB, kr, defaultHostKey, defaultAuthKeys))
	cmd.AddCommand(newRelayAddKeyCmd(defaultAuthKeys))
	return cmd
}

func newRelayServeCmd(openDB func() (*db.DB, error), kr encrypt.Keyring, defaultHostKey, defaultAuthKeys string) *cobra.Command {
	var listen, hostKey, authKeys string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "run the relay in the foreground until SIGINT/SIGTERM",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateListen(listen); err != nil {
				return err
			}
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", listen, err)
			}
			defer ln.Close()

			srv := &relay.Server{
				HostKeyPath:  hostKey,
				AuthKeysPath: authKeys,
				OpenDB:       openDB,
				Keyring:      kr,
				Logger:       slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)),
				// Bridge is nil until slice 3. Every request that passes the
				// front door's checks is refused as an internal fault until then.
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(cmd.ErrOrStderr(), "patvault relay listening on %s\n", ln.Addr())
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to bind, as <ip:port> (required)")
	cmd.Flags().StringVar(&hostKey, "host-key", defaultHostKey, "path to the relay's SSH host key")
	cmd.Flags().StringVar(&authKeys, "authorized-keys", defaultAuthKeys, "path to the agent-key allowlist")
	return cmd
}

func newRelayAddKeyCmd(defaultAuthKeys string) *cobra.Command {
	var authKeys string

	cmd := &cobra.Command{
		Use:   "add-key <path-to-pubkey>",
		Short: "append an agent's public key to the allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			added, err := relay.AddKey(authKeys, args[0])
			if err != nil {
				return err
			}
			if added {
				fmt.Fprintf(cmd.OutOrStdout(), "patvault: key added to %s\n", authKeys)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "patvault: key already authorized in %s\n", authKeys)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&authKeys, "authorized-keys", defaultAuthKeys, "path to the agent-key allowlist")
	return cmd
}

// validateListen requires an explicit IP and port.
//
// The base spec forbids auto-detecting the host-only interface and forbids
// binding a wildcard: this is a security boundary, and guessing it wider than
// intended is the one configuration mistake here with a real consequence. A
// hostname is refused too — it can resolve to more than the operator meant.
func validateListen(addr string) error {
	if addr == "" {
		return errors.New("--listen <ip:port> is required (e.g. --listen 192.168.64.1:2222)")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("--listen %q: missing port", addr)
	}
	if host == "" {
		return fmt.Errorf("--listen %q binds every interface; give the host-only interface IP explicitly", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("--listen %q: host must be an IP address, not a name", addr)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("--listen %q binds every interface; give the host-only interface IP explicitly", addr)
	}
	return nil
}
```

Note the import block above deliberately omits `"os"` and `"context"`:
`signal.NotifyContext` takes `cmd.Context()`, so neither is referenced. The exact
set is `errors`, `fmt`, `log/slog`, `net`, `os/signal`, `syscall`, `cobra`, `db`,
`encrypt`, `relay`.

Now wire it into `cmd/patvault/main.go`. Add to the `main()` command list, after
`root.AddCommand(buildCredentialCmd())`:

```go
	root.AddCommand(buildRelayCmd())
```

and add these functions:

```go
func defaultRelayHostKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "patvault:", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".config", "patvault", "relay_host_ed25519")
}

func defaultRelayAuthKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "patvault:", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".config", "patvault", "relay_authorized_keys")
}

func buildRelayCmd() *cobra.Command {
	return commands.NewRelayCmd(openDB, selectKeyring(), defaultRelayHostKeyPath(), defaultRelayAuthKeysPath())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/commands/...`
Expected: PASS.

Run: `go build ./... && go vet ./...`
Expected: no output from either.

Confirm the command surface matches the spec:

Run: `go run ./cmd/patvault relay --help`
Expected: lists `add-key` and `serve`.

Run: `go run ./cmd/patvault relay serve`
Expected: exits non-zero with `--listen <ip:port> is required`.

Run: `go run ./cmd/patvault relay serve --listen 0.0.0.0:2222`
Expected: exits non-zero with a message about binding every interface.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/authkeys.go internal/commands/relay.go internal/commands/relay_test.go cmd/patvault/main.go
git commit -m "$(cat <<'EOF'
feat: patvault relay serve / add-key

Cobra wiring for the front door, in the repo's existing injection style: the
command hands the server the DB open func and the keyring.

--listen is required and must be an explicit IP:port. The spec forbids
auto-detecting the host-only interface because guessing a security boundary wider
than intended is the one configuration mistake here with a real consequence, so
a wildcard, a bare port, and a hostname are all refused rather than resolved.

serve runs in the foreground until SIGINT/SIGTERM, then stops accepting and
drains. Its Bridge is nil until slice 3, so a request that passes every front-door
check is refused as an internal fault -- which is the whole of what this slice
claims to do.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: the anti-drift gate — a real `git` is refused

The implementation design's rule: **every slice after the first ends with real
`git` driving the real relay.** Not a unit test, not a mock — the actual `git`
binary, as a subprocess.

**This test asserts the message, not the exit code.** Real `git clone` reports
128 for every remote refusal regardless of what the relay sent (see §"What is
pinned"). The exit codes are already pinned by Tasks 5–6 through an SSH client.
What this test proves is the half no unit test can: that the `patvault:` line
survives git's own transport and reaches the user's terminal.

**Files:**
- Create: `internal/relay/relay_e2e_test.go`

**Interfaces:**
- Consumes: everything above. Adds no production code.

- [ ] **Step 1: Write the failing test**

Create `internal/relay/relay_e2e_test.go`:

```go
package relay

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// requireGit skips when the binaries this test drives are absent. The test is
// hermetic otherwise: it binds 127.0.0.1:0 and needs no credentials and no
// network, exactly as spike/relay-ssh does.
func requireGit(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"git", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH: %v", bin, err)
		}
	}
}

// writeClientKey writes signer's private key in OpenSSH format and returns its
// path, for ssh -i.
func writeClientKey(t *testing.T, dir string, key any) string {
	t.Helper()
	blk, err := ssh.MarshalPrivateKey(key, "patvault relay test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

// runGit drives the real git binary at the relay.
//
// GIT_SSH_COMMAND starts with the word "ssh" on purpose: git sniffs the ssh
// variant from it and only adds "-o SendEnv=GIT_PROTOCOL" when it recognizes
// OpenSSH. That sniffing is exactly what makes the v2 gate reachable, so do not
// bypass it with ssh.variant.
func runGit(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_SSH_COMMAND=ssh -i "+keyPath+
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"+
			" -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		"GIT_TERMINAL_PROMPT=0",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %v unexpectedly succeeded:\n%s", args, out)
	}
	return string(out)
}

// The slice gate. A real git, refused by a real relay, must show the operator the
// spec's patvault: line.
//
// Only the message is asserted. git rewrites every remote refusal to its own exit
// 128 and discards the relay's exit-status, so an exit-code assertion here would
// pass for the wrong reason; Tasks 5-6 pin the codes through an ssh client, which
// propagates them verbatim.
func TestRealGitIsRefusedWithThePatvaultMessage(t *testing.T) {
	requireGit(t)

	priv, signer := newE2EKey(t)
	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, priv)

	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	past := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Unix()
	storePAT(t, s.OpenDB, s.Keyring, "owner/stale", "ghp_stale", &past)
	storePAT(t, s.OpenDB, s.Keyring, "owner/live", "ghp_live", nil)
	addr := startRelay(t, s)

	tests := []struct {
		name    string
		repo    string
		env     []string
		want    string
		wantNot string
	}{
		{
			name: "no stored PAT",
			repo: "/owner/never-added.git",
			want: "patvault: no token stored for github.com/owner/never-added",
		},
		{
			name: "expired PAT",
			repo: "/owner/stale.git",
			want: "patvault: token for github.com/owner/stale expired 2026-07-01",
		},
		{
			// The gate must catch a real v0 client, not just a synthetic one.
			name: "fetch without protocol v2",
			repo: "/owner/live.git",
			env:  []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=0"},
			want: "patvault: relay requires git wire protocol v2",
		},
		{
			// The case the relay-ssh note says a presence-only gate admits.
			name: "fetch announcing v1 is not admitted",
			repo: "/owner/live.git",
			env:  []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=1"},
			want: "patvault: relay requires git wire protocol v2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "ssh://git@" + addr + tc.repo
			out := runGit(t, dir, keyPath, tc.env, "clone", url, filepath.Join(t.TempDir(), "clone"))
			if !strings.Contains(out, tc.want) {
				t.Errorf("git output did not carry the refusal.\nwant: %q\ngot:\n%s", tc.want, out)
			}
			// The refusal must never carry the token it refused to use.
			for _, secret := range []string{"ghp_stale", "ghp_live"} {
				if strings.Contains(out, secret) {
					t.Errorf("git output leaked a PAT:\n%s", out)
				}
			}
		})
	}
}

// An unlisted key never gets far enough to see a patvault: message — it is
// refused at authentication, which is the correct place.
func TestRealGitWithUnlistedKeyIsRefusedAtAuth(t *testing.T) {
	requireGit(t)

	_, listed := newE2EKey(t)
	intruderPriv, _ := newE2EKey(t)

	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, intruderPriv)

	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(listed.PublicKey())))
	storePAT(t, s.OpenDB, s.Keyring, "owner/live", "ghp_live", nil)
	addr := startRelay(t, s)

	out := runGit(t, dir, keyPath, nil,
		"clone", "ssh://git@"+addr+"/owner/live.git", filepath.Join(t.TempDir(), "clone"))
	if strings.Contains(out, "ghp_live") {
		t.Errorf("output leaked a PAT:\n%s", out)
	}
	if !strings.Contains(out, "Permission denied") && !strings.Contains(out, "publickey") {
		t.Errorf("want an authentication refusal, got:\n%s", out)
	}
}
```

`newE2EKey` returns the raw private key (needed for the on-disk file) alongside
the signer. Add it to `relay_e2e_test.go`, and add `"crypto/ed25519"` and
`"crypto/rand"` to that file's imports:

```go
// newE2EKey returns an ed25519 private key and its ssh.Signer. Unlike
// server_test.go's newSigner, it hands back the raw private key too, because
// this test's client is the real ssh binary and needs the key on disk for -i.
func newE2EKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return priv, signer
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/relay/ -run TestRealGit -v`
Expected: **PASS.** This task inverts the usual TDD order on purpose — it is a
gate, not a feature. Every path it drives was built in Tasks 1–6, so a real `git`
should already be refused correctly; the test exists to prove that against a real
client rather than a fake one.

**If it fails, that is the anti-drift rule doing its job** — a real client just
disagreed with the unit tests, and the unit tests are the ones that were wrong.
Fix the relay, and add a unit test in `server_test.go` that reproduces the
disagreement so it stays caught. Do not edit this test to match the bug.

Expected skip: if `git` or `ssh` is not on PATH, `requireGit` skips. A skip is
**not** a pass — the slice gate is not met on a machine that cannot run it.

- [ ] **Step 3: No new implementation**

This task adds no production code. It exists to prove the front door refuses a
real client with the spec's wording. If Step 2 required a production change,
that change *is* this task's finding — note it in the commit message.

- [ ] **Step 4: Run the full slice gate**

Run: `go test -race -count=1 ./...`
Expected: PASS for every package.

Run: `go vet ./...`
Expected: no output.

Run: `gofmt -l internal/relay internal/commands cmd/patvault`
Expected: no output.

Run: `git diff --exit-code go.mod go.sum`
Expected: no diff — this slice adds no dependencies.

Run: `go list -deps ./internal/relay | grep patvault`
Expected: exactly `.../internal/db`, `.../internal/encrypt`, `.../internal/relay`,
`.../internal/urlparse`. **No `internal/github`, no `net/http`** — there is no
upstream in this slice.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/relay_e2e_test.go
git commit -m "$(cat <<'EOF'
test: a real git, refused by a real relay, shows the patvault: line

The slice 2 gate, per the implementation design's anti-drift rule: every slice
after the first ends with the actual git binary driving the actual relay. Local
and hermetic -- binds 127.0.0.1:0, no credentials, no network -- the same way the
spikes are.

It asserts the message and deliberately not the exit code. A probe against git
2.53.0 while planning this slice found that git clone reports its own 128 for any
remote refusal and discards the relay's exit-status: sent 1, git says 128; sent
128, git says 128. Raw ssh propagates it verbatim. So the codes are pinned in
server_test.go through an ssh client, and this test proves the half no unit test
can -- that the patvault: wording survives git's transport to the operator's
terminal.

The v0 and v1 rows drive a real git configured down to those versions, which is
what makes the value-not-presence gate an observation rather than a claim.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Slice gate

Slice 2 is done when:

- `go test -race -count=1 ./...` passes, including `TestRealGit*`.
- `go vet ./...` is silent; `gofmt -l internal/relay internal/commands cmd/patvault` is empty.
- `go list -deps ./internal/relay | grep patvault` prints only `internal/db`,
  `internal/encrypt`, `internal/relay`, `internal/urlparse` — **no HTTP, no
  upstream**.
- `git diff --exit-code go.mod go.sum` — no new dependencies.
- `go run ./cmd/patvault relay serve` fails with the required-`--listen` error,
  and `--listen 0.0.0.0:2222` is refused.
- A **real `git clone`** through the relay shows the spec's `patvault:` line for:
  an unlisted key, a v0 fetch, a v1 fetch, a `git-upload-archive`, a repo with no
  stored PAT, and an expired PAT.

That list is the implementation design's promise for this slice: "a large share
of the spec's error table, and the whole fail-before-first-byte invariant, are
testable *without any upstream*."

## Out of scope (do not build these here)

- `bridge.go`, the exported `Bridge` struct, the advertisement GET, the
  `# service=` banner strip, the v2 command pump, PAT injection, sideband
  pass-through — **slices 3–4**. This slice's `bridge` interface is a name and
  nothing more; `Server.Bridge` stays nil.
- The three upstream error rows (GitHub 401/403, 404, 5xx/network) — **slice 3**,
  which will have an upstream to raise them from. See §"Scope decision".
- `pktline.go`'s `readPacket` / `readCommand` — slice 1 built them; the bridge
  consumes them in slice 3. This slice does not touch a pkt-line.
- Real-GitHub verification — **slice 5**.
- Per-key → repo scoping. v1's flat authorization (any listed key reaches any
  stored repo) is a **known, accepted** limitation of the design, not a bug to fix
  here.
