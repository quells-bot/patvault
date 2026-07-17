# Relay Slice 3 — Fetch Bridge + Stub Upstream Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `bridge.go`'s v2 fetch path — advertisement GET, `# service=` banner+flush strip, and the stateless-rpc command pump — and wire it into the relay so that a **real `git clone`** and an incremental **`git fetch`** succeed end-to-end against a git-backed stub upstream.

**Architecture:** `Bridge` is a server-side re-implementation of git's `remote-curl`: it speaks v2 smart-HTTP to GitHub, injects the stored PAT as HTTP Basic auth, and pumps framed pkt-lines between the SSH channel and HTTP bodies **without interpreting them**. `Client` and `BaseURL` are injected so tests point the bridge at an `httptest.Server`. The fetch path is half-duplex in time (read the advertisement, forward it; then loop: read one client command, POST it, pump the response) — which is what makes the aliased `ssh.Channel`-as-both-`in`-and-`out` safe (see the slice-3 handoff note). Push ships as a refusing stub; slice 4 fills it in.

**Tech Stack:** Go standard library (`bytes`, `context`, `errors`, `fmt`, `io`, `net/http`, `os`, `os/exec`, `path/filepath`, `strings`, `sync`, `testing`), existing dependencies `golang.org/x/crypto/ssh` and `github.com/spf13/cobra`, and the existing `internal/relay` (`pktline.go`'s `readPacket`/`readCommand`, `server.go`'s `bridge` interface + `Request` + `gitProtocolV2`, `errors.go`'s `relayError`) and `internal/commands` packages. No new dependencies.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-15-relay-design.md` is authoritative; `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` (§"Slice 3 — stub upstream + fetch bridge") and `docs/superpowers/notes/2026-07-17-relay-slice-3-channel-aliasing.md` define this slice's scope and the channel-aliasing contract. Do not implement slice 4 (push body / sideband emit) or slice 5 (real GitHub) here.
- Go version: module targets `go 1.26.5` (from `go.mod`). Do not lower it.
- **No new dependencies.** `go.mod` / `go.sum` must be unchanged at the end of this slice. Everything needed (`net/http`, `x/crypto/ssh`, `cobra`) is already required.
- **Testing framework:** standard library `testing` only. No `testify`, no `gomock`. Table-driven tests with `{name, ...}` struct slices and `t.Run(tc.name, ...)`, per `AGENTS.md` §Testing.
- **Package:** `internal/relay/` (`package relay`) and `internal/commands/` (`package commands`). Tests are in-package, matching how the repo tests unexported functions directly.
- **Visibility:** the `Bridge` struct and its `Client` / `BaseURL` fields are exported (slice 2 named `Bridge` as slice 3's exported type satisfying the unexported `bridge` interface). Everything else added here stays unexported. Do not export new helpers.
- **Reuse, do not reimplement:** the fetch pump reads client commands with slice 1's `readCommand` and the advertisement's banner/flush with slice 1's `readPacket` (`internal/relay/pktline.go`). Do not write a second pkt-line reader. PAT injection reuses `Request.PAT` (already decrypted by `server.resolve`). URL building appends `"<repo>.git"` to `BaseURL`.
- **The bridge never sees an `ssh.Channel`** — it takes `io.Reader` / `io.Writer`. `bridge_test.go` drives it with `bytes.Buffer` / spy writers and an `httptest.Server`; no SSH.
- **Fail-before-first-byte is the bridge's invariant:** nothing is written to `out` until the advertisement GET returns 2xx. A non-2xx advertisement returns a `*relayError` (the upstream error rows) before any byte reaches the client.
- **Stream, never buffer:** every body transfer is `io.Copy` (or `readPacket`'s exact-length reads). No `io.ReadAll` of a response into memory; no `bufio.Reader` on `in` or the response (read-ahead eats bytes the client never gets back — see the channel-aliasing note).
- **No loopback:** the bridge must never `io.Copy(out, in)`. It reads commands from `in` and writes *responses* to `out`; echoing the client's own bytes back corrupts the protocol. Pinned by a unit test.
- **Never log the PAT** (base spec §"Operational logging"). The bridge does not log; `server.refuse` already owns the operational log.
- Naming: `Test<FunctionName><Scenario>` — e.g. `TestFetchStripsServiceBanner`.
- Exported identifiers get doc comments; unexported helpers that encode a spike- or probe-pinned contract carry one too.
- Gate for the whole slice: see §Slice gate. It is a **real `git clone` + real incremental `git fetch`** through the relay, per the implementation design's anti-drift rule.

## What is pinned (these are the plan's inputs)

### From the slice-3 handoff note (`2026-07-17-relay-slice-3-channel-aliasing.md`)

`server.go`'s `dispatch` hands the bridge the **same** `ssh.Channel` as both `in` and `out`:

```go
// internal/relay/server.go (slice 2)
switch op {
case opFetch:
    err = s.Bridge.Fetch(ctx, req, ch, ch)
case opPush:
    err = s.Bridge.Push(ctx, req, ch, ch)
}
```

This is deliberate and safe because `ssh.Channel` is duplex (read and write are independent directions), **provided the bridge is half-duplex in time**: read the request, then write the response. Git's transports are exactly request-then-response. The plan's contract for the bridge:

- **Do not `io.Copy(out, in)`** — that echoes the client's bytes back into the read side. Pinned by `TestFetchDoesNotLoopbackClientBytes`.
- **Do not close `in` or `out`** — they are the same channel; `Close()` closes both halves. The bridge returns; `dispatch` owns `ch.Close()`.
- **Do not wrap `in` in a buffered reader that discards on EOF** — read-ahead eats bytes the client never gets back. `readPacket` / `readCommand` read exact lengths with `io.ReadFull`, no buffer; keep it that way.
- Read each client command to its terminating flush-pkt (`readCommand` returns `io.EOF` when the client is done), then **stop reading** and write the response. Half-duplex in time.

### From a probe run while writing this plan (2026-07-17) — read this, it fixes the stub

The e2e stub upstream shells out to `git upload-pack --stateless-rpc` (what `git http-backend` runs internally), so the packfile framing the relay pumps is produced by real git, not invented. Probed against git 2.53.0, Go 1.26.5, `git --exec-path` = `/usr/lib/git-core`:

1. **`git upload-pack --stateless-rpc --advertise-refs <repo>` with `GIT_PROTOCOL=version=2` emits the v2 advertisement with NO `# service=` banner.** Observed first bytes: `000eversion 2\n001bagent=git/2.53.0-Linux\n…0000`. The smart-HTTP `# service=git-upload-pack\n` banner + flush is prepended by `git http-backend`, not by upload-pack. **Consequence:** the e2e stub's GET handler must prepend the banner pkt-line + flush itself before piping upload-pack's output. (The unit-test stub does the same with canned bytes.)
2. **`git upload-pack --stateless-rpc <repo>` reads one v2 command from stdin and emits a real, sideband-framed packfile.** Observed fetch-response first bytes: `000dpackfile\n000b\x01PACK…` — the `packfile` section header is a pkt-line, then the pack bytes ride sideband channel 1 (`\x01`). **Consequence:** the bridge must pump the POST response verbatim and never reframe; the stub produces the framing by delegating to git, so the test asserts against ground truth.

### From the spikes (unchanged, already load-bearing in slices 1–2)

- Upstream auth is HTTP Basic `x-access-token:<PAT>`, not Bearer — on both endpoints (relay-v2, relay-push).
- The `# service=git-upload-pack` pkt-line + flush prefixes the smart-HTTP advertisement and must be stripped for the SSH transport (relay-v2 `checkAdvertisement`).

### Spec wording to copy verbatim

The three upstream error rows from the base spec's §"Errors and exit codes" table (slice 2 deferred them; this slice adds them to `errors.go`):

| Condition | stderr message | retry | exit |
|---|---|---|---|
| GitHub 401/403 | `patvault: github rejected the token for owner/repo (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then` | terminal | 1 |
| GitHub 404 | `patvault: owner/repo not found, or the stored token cannot see it` | terminal | 1 |
| GitHub 5xx / network | `patvault: github unreachable (503); safe to retry shortly` | retryable | 1 |

Note these rows use `owner/repo` (no `github.com/` host prefix, unlike the PAT rows which say `github.com/owner/repo`) — the message already names "github", so the host is redundant. Copy the wording exactly.

The spec flags this status→message mapping as **inferred, not observed** (§"Unverified assumptions"); slice 5 confirms each row against the real Git endpoints. Add the rows now (slice 2's `errors.go` is "the only departure from the [module layout] table" and is meant to own the whole table), with a code comment noting they are unverified.

## File Structure

| Path | Responsibility |
|---|---|
| `internal/relay/errors.go` | ADD the three upstream error constructors: `errGitHubAuth`, `errGitHubNotFound`, `errGitHubUnreachable`. Constructors only; no logic (matches slice 2's file responsibility). |
| `internal/relay/errors_test.go` | ADD table rows + a network-failure form test for the three new constructors. |
| `internal/relay/bridge.go` | CREATE. `Bridge` struct, `Fetch` (advertisement GET + banner strip + command pump), `Push` (refusing stub), URL construction, upstream header injection, HTTP status → error mapping. |
| `internal/relay/bridge_test.go` | CREATE. Unit tests against an `httptest.Server` stub: banner strip, header injection, command pump verbatim, no-loopback, fail-before-first-byte, status mapping, streaming-without-buffering, context cancellation, push stub. Owns the shared `writePkt`/`writeFlush` test helpers. |
| `internal/relay/relay_e2e_test.go` | ADD the slice gate: real `git clone` + incremental `git fetch` through the relay backed by a `git-upload-pack` stub upstream. Adds `requireUploadPack`, `uploadPackRepo`, `newStubUpstreamServer`, `makeSourceRepo`, `mustRun`, `runGitOK`, `gitEnv` helpers. |
| `internal/commands/relay.go` | Wire the production `Bridge` into `serve` via an extracted `buildServeServer` helper (thin cobra wrapper, logic in helper — matches repo convention). |
| `internal/commands/relay_test.go` | ADD a test that `buildServeServer` wires a non-nil `Bridge` pointed at `https://github.com`. |

`bridge.go` is one file with one responsibility (the upstream pump), per the base spec's module layout. Do not split it.

---

### Task 1: Upstream error rows in `errors.go`

**Files:**
- Modify: `internal/relay/errors.go` (append three constructors)
- Test: `internal/relay/errors_test.go` (add table rows + one new test)

**Interfaces:**
- Consumes: `relayError` (slice 2), `upstreamHost` (slice 2, unused here — the upstream rows format with bare `repo`).
- Produces:
  ```go
  func errGitHubAuth(repo string) *relayError
  func errGitHubNotFound(repo string) *relayError
  func errGitHubUnreachable(status int) *relayError
  ```

- [ ] **Step 1: Write the failing tests**

Open `internal/relay/errors_test.go`. Add three rows to the existing `TestRelayErrorTable` slice (after the "internal fault" case, before the closing `}`):

```go
		{
			name: "github 401/403",
			err:  errGitHubAuth("owner/repo"),
			want: "patvault: github rejected the token for owner/repo (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then",
			exit: 1,
			retryable: false,
		},
		{
			name: "github 404",
			err:  errGitHubNotFound("owner/repo"),
			want: "patvault: owner/repo not found, or the stored token cannot see it",
			exit: 1,
			retryable: false,
		},
		{
			name: "github 5xx",
			err:  errGitHubUnreachable(503),
			want: "patvault: github unreachable (503); safe to retry shortly",
			exit: 1,
			retryable: true,
		},
```

Then append a new test at the end of the file:

```go
// A transport-level failure (DNS, refused, timeout) has no HTTP status. The
// spec's "(503)" is an example for the 5xx case; a network failure omits the
// parenthetical rather than inventing a code, and stays retryable.
func TestErrGitHubUnreachableOmitsCodeForNetworkFailure(t *testing.T) {
	err := errGitHubUnreachable(0)
	want := "patvault: github unreachable; safe to retry shortly"
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n%q\nwant\n%q", got, want)
	}
	if !err.Retryable() {
		t.Error("Retryable() = false, want true")
	}
	if err.Exit() != 1 {
		t.Errorf("Exit() = %d, want 1", err.Exit())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: errGitHubAuth`, `undefined: errGitHubNotFound`, `undefined: errGitHubUnreachable`.

- [ ] **Step 3: Write the implementation**

Append to `internal/relay/errors.go` (after `errInternal`):

```go
// errGitHubAuth is the 401/403 row: GitHub rejected the token. The wording is
// the base spec's §"Errors and exit codes" table, copied verbatim. The spec
// marks this status→message mapping as inferred, not observed (§"Unverified
// assumptions"); slice 5 confirms it against the real Git endpoints. The repo is
// formatted bare (no host prefix) — the message already names "github".
func errGitHubAuth(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: github rejected the token for %s (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then",
			repo),
		exit:      1,
		retryable: false,
	}
}

// errGitHubNotFound is the 404 row: the repo does not exist, or the token cannot
// see it. GitHub's Git endpoint returns 404 for both a missing repo and a
// private repo the token lacks access to — the same existence-hiding ambiguity
// the REST API uses.
func errGitHubNotFound(repo string) *relayError {
	return &relayError{
		msg: fmt.Sprintf(
			"patvault: %s not found, or the stored token cannot see it",
			repo),
		exit:      1,
		retryable: false,
	}
}

// errGitHubUnreachable is the 5xx / network row. status is the HTTP status code
// when one was received, or 0 for a transport-level failure (DNS, refused,
// timeout). The "(503)" in the spec's table is an example; the code is
// interpolated so 502/503/504 all read correctly, and a network failure omits
// the parenthetical rather than inventing a code. Always retryable.
func errGitHubUnreachable(status int) *relayError {
	qualifier := ""
	if status > 0 {
		qualifier = fmt.Sprintf(" (%d)", status)
	}
	return &relayError{
		msg:       fmt.Sprintf("patvault: github unreachable%s; safe to retry shortly", qualifier),
		exit:      1,
		retryable: true,
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/errors.go internal/relay/errors_test.go
git commit -m "feat(relay): add upstream error rows to the error table

The 401/403, 404, and 5xx/network rows slice 2 deferred. Wording is the base
spec's §Errors table verbatim; the status→message mapping is flagged as
unverified (slice 5 confirms it against real GitHub).
"
```

---

### Task 2: `Bridge` advertisement — GET, banner strip, headers, fail-before-first-byte

This task creates `bridge.go` with the `Bridge` struct, the advertisement phase of `Fetch` (GET, strip the `# service=` banner + flush, forward the rest, inject headers, map non-2xx to the upstream error rows before writing a byte), and a `Push` stub so `*Bridge` satisfies the `bridge` interface. The command pump (the loop that POSTs client commands) is Task 3; here `Fetch` returns after the advertisement.

**Files:**
- Create: `internal/relay/bridge.go`
- Test: `internal/relay/bridge_test.go`

**Interfaces:**
- Consumes:
  - `readPacket(r io.Reader) (payload []byte, kind int, err error)` and `pktData` / `pktFlush` from `internal/relay/pktline.go` (slice 1).
  - `gitProtocolV2 == "version=2"` from `internal/relay/server.go` (slice 2).
  - `Request{Repo, PAT}` and the `bridge` interface from `internal/relay/server.go` (slice 2).
  - `errGitHubAuth` / `errGitHubNotFound` / `errGitHubUnreachable` / `errInternal` from `internal/relay/errors.go`.
- Produces:
  ```go
  type Bridge struct {
      Client  *http.Client
      BaseURL string
  }
  func (b *Bridge) Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error
  func (b *Bridge) Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
  // unexported: endpoint, trimSlash, advertise, setUpstreamHeaders, classifyStatus
  ```
  `*Bridge` satisfies the unexported `bridge` interface (slice 2), so `Server.Bridge = &Bridge{...}` compiles.

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/bridge_test.go`:

```go
package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// writePkt writes s as one pkt-line (4-byte hex length prefix + payload). Test
// helper only — production pumps bytes verbatim and never writes pkt-lines.
func writePkt(w io.Writer, s string) {
	fmt.Fprintf(w, "%04x%s", len(s)+4, s)
}

// writeFlush writes a flush-pkt ("0000").
func writeFlush(w io.Writer) {
	io.WriteString(w, "0000")
}

// stubAdvertisement is a real-shape v2 advertisement (the capability list git
// 2.53.0 emits), prefixed with the smart-HTTP "# service=" banner + flush that
// the SSH transport does not use and the bridge must strip.
func stubAdvertisement() []byte {
	var b strings.Builder
	writePkt(&b, "# service=git-upload-pack\n")
	writeFlush(&b)
	writePkt(&b, "version 2\n")
	writePkt(&b, "agent=git/2.53.0-Linux\n")
	writePkt(&b, "ls-refs=unborn\n")
	writePkt(&b, "fetch=shallow wait-for-done\n")
	writePkt(&b, "server-option\n")
	writePkt(&b, "object-format=sha1\n")
	writeFlush(&b)
	return []byte(b.String())
}

// advWithoutBanner is stubAdvertisement with the banner+flush removed — what the
// bridge must write to out.
func advWithoutBanner() []byte {
	full := stubAdvertisement()
	// Drop the first two packets (banner data + flush) by parsing with readPacket.
	r := bytes.NewReader(full)
	readPacket(r) // banner
	readPacket(r) // flush
	rest, _ := io.ReadAll(r)
	return rest
}

// stubReq records one upstream request's headers and body.
type stubReq struct {
	auth, gitProto, accept, ctype string
	body                          []byte
}

// stubUpstream is a minimal smart-HTTP upload-pack upstream. It returns canned
// bytes so the bridge's framing, header injection, and error mapping can be
// asserted without a pack. adv is the GET body; postResp is a factory called
// per POST. A non-zero status short-circuits the response with that code.
type stubUpstream struct {
	*httptest.Server
	mu        sync.Mutex
	gets      []stubReq
	posts     []stubReq
	adv       []byte
	postResp  func() io.Reader
	getStatus int
	postStatus int
}

func newStubUpstream(t *testing.T, adv []byte, postResp func() io.Reader, getStatus, postStatus int) *stubUpstream {
	t.Helper()
	s := &stubUpstream{adv: adv, postResp: postResp, getStatus: getStatus, postStatus: postStatus}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		rec := stubReq{
			auth: r.Header.Get("Authorization"), gitProto: r.Header.Get("Git-Protocol"),
			accept: r.Header.Get("Accept"), ctype: r.Header.Get("Content-Type"), body: body,
		}
		s.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "info/refs"):
			s.mu.Lock(); s.gets = append(s.gets, rec); s.mu.Unlock()
			if s.getStatus != 0 {
				w.WriteHeader(s.getStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.Write(s.adv)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-upload-pack"):
			s.mu.Lock(); s.posts = append(s.posts, rec); s.mu.Unlock()
			if s.postStatus != 0 {
				w.WriteHeader(s.postStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			io.Copy(w, s.postResp())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func (s *stubUpstream) recordedGets() []stubReq {
	s.mu.Lock(); defer s.mu.Unlock()
	return append([]stubReq(nil), s.gets...)
}
func (s *stubUpstream) recordedPosts() []stubReq {
	s.mu.Lock(); defer s.mu.Unlock()
	return append([]stubReq(nil), s.posts...)
}

// basicAuth returns the decoded "user:pass" for an Authorization header, or "".
func basicAuth(h string) string {
	if !strings.HasPrefix(h, "Basic ") {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return ""
	}
	return string(b)
}

func TestFetchStripsServiceBannerAndForwardsAdvertisement(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(), func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if got := out.Bytes(); !bytes.Equal(got, advWithoutBanner()) {
		t.Errorf("out =\n%q\nwant advertisement without banner:\n%q", got, advWithoutBanner())
	}
	if bytes.Contains(out.Bytes(), []byte("# service=")) {
		t.Errorf("out still contains the # service= banner:\n%q", out.Bytes())
	}
	if len(stub.recordedGets()) != 1 {
		t.Errorf("recorded %d GETs, want 1", len(stub.recordedGets()))
	}
}

func TestFetchInjectsUpstreamHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(), func() io.Reader { return bytes.NewReader([]byte("resp")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	// in is EOF, so only the advertisement GET happens (the command pump lands
	// in Task 3). Assert the GET headers here; the POST headers are asserted in
	// Task 3's TestFetchInjectsPostHeaders.
	var out bytes.Buffer
	_ = b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, strings.NewReader(""), &out)

	gets := stub.recordedGets()
	if len(gets) != 1 {
		t.Fatalf("recorded %d GETs, want 1", len(gets))
	}
	g := gets[0]
	if got := basicAuth(g.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("GET Authorization = %q, want Basic x-access-token:ghp_secret", g.auth)
	}
	if g.gitProto != "version=2" {
		t.Errorf("GET Git-Protocol = %q, want version=2", g.gitProto)
	}
	if g.accept != "application/x-git-upload-pack-advertisement" {
		t.Errorf("GET Accept = %q, want advertisement", g.accept)
	}
}

func TestFetchFailBeforeFirstByteOn500(t *testing.T) {
	stub := newStubUpstream(t, nil, nil, http.StatusInternalServerError, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0 (fail-before-first-byte): %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(500)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("Fetch returned %v, want a *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("Fetch error = %v (retryable %v), want %v (retryable true)", re, re.Retryable(), want)
	}
}

func TestFetchMapsUpstreamStatusToErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   *relayError
	}{
		{"401 maps to auth", http.StatusUnauthorized, errGitHubAuth("owner/repo")},
		{"403 maps to auth", http.StatusForbidden, errGitHubAuth("owner/repo")},
		{"404 maps to not-found", http.StatusNotFound, errGitHubNotFound("owner/repo")},
		{"502 maps to unreachable", http.StatusBadGateway, errGitHubUnreachable(502)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubUpstream(t, nil, nil, tc.status, 0)
			b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}
			err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), io.Discard)
			var re *relayError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want *relayError", err)
			}
			if re.Error() != tc.want.Error() || re.Retryable() != tc.want.Retryable() {
				t.Errorf("got %q (retryable %v), want %q (retryable %v)", re, re.Retryable(), tc.want, tc.want.Retryable())
			}
		})
	}
}

func TestFetchMapsNetworkErrorToUnreachable(t *testing.T) {
	// Point the bridge at a closed port to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0: %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(0)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("got %q, want %q", re, want)
	}
}

func TestPushReturnsErrorUntilSlice4(t *testing.T) {
	b := &Bridge{Client: &http.Client{}, BaseURL: "stub"}
	err := b.Push(context.Background(), Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("Push returned nil; slice 3 must refuse pushes")
	}
	// The error must NOT be a *relayError, so dispatch maps it to errInternal
	// (clientError in server.go), matching slice 2's nil-bridge behavior.
	var re *relayError
	if errors.As(err, &re) {
		t.Errorf("Push returned a *relayError %v; want a plain error dispatch maps to internal", err)
	}
}

```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: Bridge` (and the `Fetch`/`Push` methods).

- [ ] **Step 3: Write the implementation**

Create `internal/relay/bridge.go`:

```go
package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Bridge is the pkt-line ↔ HTTPS upstream. It is a server-side re-implementation
// of git's remote-curl: it speaks the v2 smart-HTTP protocol to GitHub, injects
// the stored PAT as HTTP Basic auth, and pumps framed pkt-lines between the SSH
// channel and HTTP bodies without interpreting them.
//
// Client and BaseURL are injected so the bridge is testable without a network:
// tests point BaseURL at an httptest.Server. Production sets BaseURL to
// "https://github.com".
type Bridge struct {
	// Client issues the upstream requests. A dedicated *http.Client with no
	// Timeout is correct: a Client.Timeout would abort large pack transfers
	// mid-stream, and cancellation is owned by the request context.
	Client *http.Client
	// BaseURL is the forge root, without a trailing slash (e.g.
	// "https://github.com"). The repo is appended as "<owner/repo>.git".
	BaseURL string
}

// Push is the receive-pack bridge. Slice 3 ships the fetch path only; push
// arrives in slice 4, where it reuses the header/pump helpers added here. Until
// then a push is refused — the error is not a *relayError, so dispatch maps it
// to the internal-fault row (server.go clientError), exactly as a nil bridge.
func (b *Bridge) Push(_ context.Context, _ Request, _ io.Reader, _ io.Writer) error {
	return errors.New("push bridge not implemented (slice 4)")
}

// Fetch runs the v2 stateless-rpc pump: the advertisement GET (banner+flush
// stripped, then forwarded), then one POST per client command, each response
// streamed back verbatim.
//
// Fail-before-first-byte is the bridge's invariant: nothing is written to out
// until the advertisement GET returns 2xx. A non-2xx advertisement is mapped to
// the spec's upstream error rows and returned before any byte reaches the
// client.
//
// The bridge is half-duplex in time (read the advertisement, write it; then
// read one command, write its response). That is what makes the aliased
// ssh.Channel-as-both-in-and-out safe: read consumes client→relay bytes, write
// produces relay→client bytes, and they never collide. See
// docs/superpowers/notes/2026-07-17-relay-slice-3-channel-aliasing.md.
func (b *Bridge) Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	if err := b.advertise(ctx, req, out); err != nil {
		return err
	}
	// The command pump is added in Task 3. Until then, after the advertisement
	// the client (in tests) sends EOF and Fetch returns cleanly.
	return b.pumpCommands(ctx, req, in, out)
}

// endpoint builds the upload-pack URL for req: "<BaseURL>/<repo>.git/<service>".
func (b *Bridge) endpoint(req Request, service string) string {
	return fmt.Sprintf("%s/%s.git/%s", trimSlash(b.BaseURL), req.Repo, service)
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// advertise does the GET, checks 2xx before writing anything, strips the
// smart-HTTP "# service=" banner + flush that the SSH transport does not use,
// and copies the remaining v2 advertisement to out verbatim.
//
// readPacket reads exact lengths with io.ReadFull (no buffering), so consuming
// the banner and flush steals no bytes from the io.Copy that follows.
func (b *Bridge) advertise(ctx context.Context, req Request, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		b.endpoint(req, "info/refs?service=git-upload-pack"), nil)
	if err != nil {
		return fmt.Errorf("build advertise request: %w", err)
	}
	setUpstreamHeaders(httpReq, req, "application/x-git-upload-pack-advertisement")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}

	// The smart-HTTP advertisement prefixes one data pkt-line (the
	// "# service=git-upload-pack" banner) and a flush-pkt that the SSH
	// transport never sends. Strip both, then pump the rest unchanged.
	if _, kind, err := readPacket(resp.Body); err != nil || kind != pktData {
		return errInternal()
	}
	if _, kind, err := readPacket(resp.Body); err != nil || kind != pktFlush {
		return errInternal()
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy advertisement: %w", err)
	}
	return nil
}

// pumpCommands loops over the client's v2 commands. Implemented in Task 3.
func (b *Bridge) pumpCommands(_ context.Context, _ Request, in io.Reader, _ io.Writer) error {
	// Task 2 stub: the advertisement is done; if the client sent nothing more
	// (test in == EOF) we are finished. Task 3 replaces this body with the
	// readCommand loop.
	_ = in
	return nil
}

// setUpstreamHeaders sets the headers every upstream request carries: the PAT
// as HTTP Basic auth (the username is the conventional x-access-token
// placeholder — GitHub's Git transport takes Basic, not Bearer), the v2
// protocol marker, and the per-request content type. The User-Agent matches
// what the relay-v2 spike sent to real GitHub and had accepted.
func setUpstreamHeaders(req *http.Request, r Request, contentType string) {
	req.SetBasicAuth("x-access-token", r.PAT)
	req.Header.Set("Git-Protocol", gitProtocolV2)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "git/2.43.0")
}

// classifyStatus maps a non-2xx upstream status to the spec's error table. The
// table marks this mapping as inferred rather than observed (§"Unverified
// assumptions"); slice 5 confirms each row against the real Git endpoints.
func classifyStatus(repo string, status int) *relayError {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return errGitHubAuth(repo)
	case status == http.StatusNotFound:
		return errGitHubNotFound(repo)
	case status >= 500:
		return errGitHubUnreachable(status)
	default:
		// A status outside the table (unexpected 4xx). Treat it as an
		// unreachable upstream rather than a silent success: the client gets a
		// retryable signal and the host log gets the code via refuse's cause.
		return errGitHubUnreachable(status)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS (all bridge tests, plus the existing slice 1–2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/relay/bridge.go internal/relay/bridge_test.go
git commit -m "feat(relay): bridge fetch advertisement + upstream error mapping

Bridge struct with injected Client/BaseURL. Fetch does the v2 advertisement GET,
strips the smart-HTTP # service= banner+flush the SSH transport does not use,
injects the PAT as Basic auth + Git-Protocol: version=2, and maps non-2xx to the
upstream error rows before writing a byte (fail-before-first-byte). Push ships as
a refusing stub until slice 4.
"
```

---

### Task 3: `Bridge` command pump — POST each client command, stream the response verbatim

This task replaces `pumpCommands`'s stub body with the real loop: `readCommand` one client command up to its flush-pkt, `POST .../git-upload-pack` with those bytes, stream the response to `out` untouched; repeat until `readCommand` returns `io.EOF`. It also pins the no-loopback invariant and the stream-never-buffer property.

**Files:**
- Modify: `internal/relay/bridge.go` (replace `pumpCommands`; add `postCommand`)
- Test: `internal/relay/bridge_test.go` (add pump, no-loopback, POST-headers, streaming, context-cancellation tests)

**Interfaces:**
- Consumes: `readCommand(r io.Reader) ([]byte, error)` from `internal/relay/pktline.go` (slice 1) — returns the raw command bytes (framing intact) and `io.EOF` when the client is done.
- Produces: the completed `Fetch`; no new exported symbols.

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/bridge_test.go`. First add `"time"` to the import block (the streaming and cancellation tests below use it; Task 2 omitted it because none of its tests needed it), then append:

```go
// A hand-rolled v2 ls-refs command, exactly the bytes a real git client sends:
// "command=ls-refs\n", "object-format=sha1\n", a delim-pkt, "ref-prefix HEAD\n",
// a flush-pkt. readCommand returns these bytes verbatim (framing intact) for
// the bridge to POST.
func lsRefsCommand() []byte {
	var b strings.Builder
	writePkt(&b, "command=ls-refs\n")
	writePkt(&b, "object-format=sha1\n")
	io.WriteString(&b, "0001") // delim-pkt
	writePkt(&b, "ref-prefix HEAD\n")
	writeFlush(&b)
	return []byte(b.String())
}

func fetchCommand() []byte {
	var b strings.Builder
	writePkt(&b, "command=fetch\n")
	writePkt(&b, "object-format=sha1\n")
	io.WriteString(&b, "0001")
	writePkt(&b, "no-progress\n")
	writePkt(&b, "want 0000000000000000000000000000000000000000\n")
	writePkt(&b, "done\n")
	writeFlush(&b)
	return []byte(b.String())
}

func TestFetchPumpsCommandsVerbatimAndInOrder(t *testing.T) {
	// Each POST returns a distinct canned response; assert they reach out in
	// order, after the advertisement, byte-for-byte.
	calls := 0
	responses := [][]byte{[]byte("LS-REFS-RESPONSE"), []byte("FETCH-RESPONSE")}
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { r := responses[calls]; calls++; return bytes.NewReader(r) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	// in = ls-refs command, then fetch command, then EOF.
	in := bytes.NewReader(append(append(lsRefsCommand(), fetchCommand()...)))
	var out bytes.Buffer
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, in, &out); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}

	want := append(advWithoutBanner(), append(responses[0], responses[1]...)...)
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant\n%q", got, want)
	}

	posts := stub.recordedPosts()
	if len(posts) != 2 {
		t.Fatalf("recorded %d POSTs, want 2", len(posts))
	}
	if !bytes.Equal(posts[0].body, lsRefsCommand()) {
		t.Errorf("POST 0 body = %q, want the ls-refs command", posts[0].body)
	}
	if !bytes.Equal(posts[1].body, fetchCommand()) {
		t.Errorf("POST 1 body = %q, want the fetch command", posts[1].body)
	}
}

func TestFetchInjectsPostHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("r")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	in := bytes.NewReader(lsRefsCommand())
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, in, io.Discard); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	p := posts[0]
	if got := basicAuth(p.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("POST Authorization = %q, want Basic x-access-token:ghp_secret", p.auth)
	}
	if p.gitProto != "version=2" {
		t.Errorf("POST Git-Protocol = %q, want version=2", p.gitProto)
	}
	if p.ctype != "application/x-git-upload-pack-request" {
		t.Errorf("POST Content-Type = %q, want request", p.ctype)
	}
	if p.accept != "application/x-git-upload-pack-result" {
		t.Errorf("POST Accept = %q, want result", p.accept)
	}
}

// The channel-aliasing note's pin: the bridge must never echo the client's own
// command bytes back to out (io.Copy(out, in) would). Assert the command bytes
// the client sent do not appear in out — only the advertisement and responses do.
func TestFetchDoesNotLoopbackClientBytes(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("RESP")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	cmd := lsRefsCommand()
	in := bytes.NewReader(cmd)
	var out bytes.Buffer
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, in, &out); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if bytes.Contains(out.Bytes(), cmd) {
		t.Errorf("client command bytes were echoed back to out (loopback):\nout=%q", out.Bytes())
	}
	if bytes.Contains(out.Bytes(), []byte("command=ls-refs")) {
		t.Errorf("command text leaked into out:\n%q", out.Bytes())
	}
}

// Stream, never buffer: the bridge must write advertisement bytes to out as they
// arrive, not hold the whole body until EOF. The GET handler writes
// banner+flush+FIRST, flushes, then waits for the bridge to deliver FIRST to out
// before ending the body. A streaming bridge closes the signal promptly; a
// buffering bridge holds FIRST until EOF, which never arrives while it waits —
// the 2s timeout distinguishes them, deterministically.
func TestFetchStreamsAdvertisementWithoutBuffering(t *testing.T) {
	first := []byte("FIRST-CHUNK")
	bridgeWrote := make(chan struct{})
	streamed := make(chan bool, 1)

	out := &signalingWriter{firstWritten: bridgeWrote}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePkt(w, "# service=git-upload-pack\n")
		writeFlush(w)
		w.Write(first)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-bridgeWrote:
			streamed <- true
		case <-time.After(2 * time.Second):
			streamed <- false
		}
	}))
	t.Cleanup(srv.Close)

	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}
	done := make(chan error, 1)
	go func() {
		done <- b.Fetch(context.Background(), Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), out)
	}()
	if err := <-done; err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if !<-streamed {
		t.Error("FIRST did not reach out before the body EOF — bridge is buffering, not streaming")
	}
	if !bytes.Contains(out.bytes, first) {
		t.Errorf("out missing FIRST: %q", out.bytes)
	}
}

// signalingWriter records all bytes written and closes firstWritten on the first
// Write — so the streaming test can observe the bridge delivering the first
// chunk before the response body is complete.
type signalingWriter struct {
	bytes        []byte
	firstWritten chan struct{}
	once         sync.Once
}

func (w *signalingWriter) Write(p []byte) (int, error) {
	w.bytes = append(w.bytes, p...)
	w.once.Do(func() { close(w.firstWritten) })
	return len(p), nil
}

func TestFetchRespectsContextCancellation(t *testing.T) {
	// A GET that never responds: the bridge must return when ctx is cancelled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := b.Fetch(ctx, Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Error("Fetch returned nil; want an error after ctx cancellation")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL — `TestFetchPumpsCommandsVerbatimAndInOrder` sees zero POSTs (the `pumpCommands` stub returns immediately without reading `in`), and the no-loopback / streaming tests fail because no responses are pumped.

- [ ] **Step 3: Write the implementation**

In `internal/relay/bridge.go`, replace the `pumpCommands` stub body with the real loop and add `postCommand`:

```go
// pumpCommands loops over the client's v2 commands: read one command up to its
// terminating flush-pkt (readCommand returns io.EOF when the client is done),
// POST it to git-upload-pack, and stream the response back to out verbatim. The
// response is never interpreted — sideband framing, section order, and pack
// bytes pass through untouched, which is what makes partial/shallow clones and
// sideband progress work for free.
//
// This is the half-duplex-in-time core: read a command, write its response,
// repeat. The bridge never writes a response while still reading a command, and
// never reads the next command while a response is in flight — so the aliased
// ssh.Channel's read and write halves never collide.
func (b *Bridge) pumpCommands(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	for {
		cmd, err := readCommand(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read client command: %w", err)
		}
		if err := b.postCommand(ctx, req, cmd, out); err != nil {
			return err
		}
	}
}

// postCommand POSTs one command (framing intact, as readCommand returned it) to
// git-upload-pack and streams the response to out verbatim. The command body is
// bounded by its flush-pkt, so Content-Length is known and the POST is not
// chunked (chunked is only the push path's concern, in slice 4).
func (b *Bridge) postCommand(ctx context.Context, req Request, cmd []byte, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.endpoint(req, "git-upload-pack"), bytes.NewReader(cmd))
	if err != nil {
		return fmt.Errorf("build command request: %w", err)
	}
	setUpstreamHeaders(httpReq, req, "application/x-git-upload-pack-request")
	httpReq.Header.Set("Accept", "application/x-git-upload-pack-result")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy command response: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS, including the pump, no-loopback, POST-headers, streaming, and cancellation tests.

If the streaming test is flaky on slow CI, increase the cancellation test's sleep — but do not weaken the no-loopback or verbatim assertions.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/bridge.go internal/relay/bridge_test.go
git commit -m "feat(relay): bridge fetch command pump with verbatim streaming

Fetch now loops over client v2 commands (readCommand up to each flush-pkt),
POSTs each to git-upload-pack with the right Content-Type/Accept, and streams the
response to out untouched — sideband framing and pack bytes pass through. Pins
the no-loopback invariant (never echo client bytes to out) and stream-never-buffer.
"
```

---

### Task 4: Wire the production `Bridge` into `patvault relay serve`

`commands/relay.go`'s `serve` left `Server.Bridge` nil (slice 2). Wire the real `Bridge` so `patvault relay serve` actually does fetches. Extract a `buildServeServer` helper (thin cobra wrapper, logic in a helper — matches repo convention) and test it.

**Files:**
- Modify: `internal/commands/relay.go` (extract `buildServeServer`; call it from `serve` RunE)
- Test: `internal/commands/relay_test.go` (add `TestBuildServeServerWiresFetchBridge`)

**Interfaces:**
- Consumes: `relay.Bridge`, `relay.Server` (slice 3 + slice 2).
- Produces: `buildServeServer(...)` in package `commands`; `patvault relay serve` now serves fetches end-to-end (pushes refuse until slice 4).

- [ ] **Step 1: Write the failing test**

Add these imports to `internal/commands/relay_test.go`, merging with the existing block and skipping any already present:

```go
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/quells-bot/patvault/internal/db"
	"github.com/quells-bot/patvault/internal/encrypt"
	"github.com/quells-bot/patvault/internal/relay"
```

Then append the test:

```go
// buildServeServer must wire a non-nil fetch Bridge pointed at GitHub, so that
// 'patvault relay serve' does fetches out of the box. (Push refuses until slice
// 4 — see relay.Bridge.Push.) The BaseURL is the one constant an operator must
// not have to set.
//
// The OpenDB func and FileKeyring are built inline from the real db.Open and
// encrypt.FileKeyring APIs (the same shape relay/server_test.go's newStore
// uses), so the test depends on no fictitious helper.
func TestBuildServeServerWiresFetchBridge(t *testing.T) {
	dir := t.TempDir()
	open := func() (*db.DB, error) { return db.Open(filepath.Join(dir, "test.db")) }
	kr := encrypt.FileKeyring{Path: filepath.Join(dir, "master.key")}
	srv := buildServeServer("/tmp/hostkey", "/tmp/authkeys", open, kr, slog.Default())
	if srv.Bridge == nil {
		t.Fatal("Bridge is nil; serve would refuse every fetch as an internal fault")
	}
	b, ok := any(srv.Bridge).(*relay.Bridge)
	if !ok {
		t.Fatalf("Bridge is %T, want *relay.Bridge", srv.Bridge)
	}
	if b.BaseURL != "https://github.com" {
		t.Errorf("BaseURL = %q, want https://github.com", b.BaseURL)
	}
	if b.Client == nil {
		t.Error("Client is nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/commands/...`
Expected: FAIL with `undefined: buildServeServer`.

- [ ] **Step 3: Write the implementation**

In `internal/commands/relay.go`, add the helper and call it from `serve`'s RunE. Replace the `srv := &relay.Server{...}` block inside RunE (the one whose comment says `// Bridge is nil until slice 3`) with:

```go
			srv := buildServeServer(hostKey, authKeys, openDB, kr,
				slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)))
```

And add the helper (place it above `newRelayServeCmd` or below `validateListen`):

```go
// buildServeServer constructs the relay Server for 'serve'. The Bridge is wired
// here (not inline in RunE) so the wiring is unit-testable without running the
// SSH server. BaseURL is the one forge the relay fronts; Client has no Timeout
// so large pack transfers are not aborted mid-stream (cancellation is the
// request context's job).
func buildServeServer(hostKey, authKeys string, openDB func() (*db.DB, error), kr encrypt.Keyring, logger *slog.Logger) *relay.Server {
	return &relay.Server{
		HostKeyPath:  hostKey,
		AuthKeysPath: authKeys,
		OpenDB:       openDB,
		Keyring:      kr,
		Logger:       logger,
		Bridge: &relay.Bridge{
			Client:  &http.Client{},
			BaseURL: "https://github.com",
		},
	}
}
```

Add `"net/http"` to the import block of `internal/commands/relay.go` if it is not already present.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/commands/...`
Expected: PASS.

- [ ] **Step 5: Verify the whole module builds and the suite is green**

Run: `go build ./cmd/patvault && go vet ./... && go test ./...`
Expected: build succeeds, vet is clean, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/commands/relay.go internal/commands/relay_test.go
git commit -m "feat(relay): wire fetch Bridge into 'patvault relay serve'

serve now constructs a relay.Bridge (http.Client + https://github.com) via a
testable buildServeServer helper, so fetches work out of the box. Pushes still
refuse until slice 4.
"
```

---

### Task 5: The slice gate — real `git clone` + incremental `git fetch` through the relay

The anti-drift gate. A real `git`, a real relay with a real `Bridge`, and a real (git-backed) stub upstream exchange real v2 bytes — including a sideband-framed packfile the relay must pump untouched. This is the only test that catches a byte-wrong bridge against ground truth.

**Files:**
- Modify: `internal/relay/relay_e2e_test.go` (add helpers + the gate test)

**Interfaces:**
- Consumes: `Bridge`, `Server` (slice 3 + slice 2); `requireGit`, `newE2EKey`, `writeClientKey`, `startRelay`, `newTestServer`, `storePAT`, `writePkt`, `writeFlush` (slice 2 + this slice's `bridge_test.go`).
- Produces: the slice gate (`TestRealGitCloneAndIncrementalFetchThroughRelay`).

- [ ] **Step 1: Write the test and helpers**

Append to `internal/relay/relay_e2e_test.go`. First add the imports the new code needs, merging into the existing block and skipping any already present: `bytes`, `io`, `net/http`, `net/http/httptest`. (The file already imports `os`, `os/exec`, `path/filepath`, `strings`, `testing`, `time`, and `golang.org/x/crypto/ssh` from slice 2.)

Add the helpers:

```go
// requireUploadPack skips when git-upload-pack is not installed. The e2e stub
// upstream shells out to it (as git http-backend does internally) so a real
// packfile — with real sideband framing the relay must not reframe — is produced
// by git itself, not invented by the test.
func requireUploadPack(t *testing.T) {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
		return
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-upload-pack")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("git-upload-pack not found at %s", bin)
	}
}

// uploadPackRepo runs git-upload-pack --stateless-rpc against repo, the way
// git http-backend does internally. When advertise is true it runs
// --advertise-refs (no stdin) and the caller prepends the smart-HTTP
// "# service=" banner+flush to the output. Otherwise it reads one v2 command
// from stdin and returns the response (refs, packfile, …) with sideband framing
// exactly as git emits it. GIT_PROTOCOL comes from the request so the stub
// mirrors the real server's protocol negotiation.
func uploadPackRepo(t *testing.T, repo string, advertise bool, gitProto string, stdin io.Reader) []byte {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-upload-pack")
	args := []string{"--stateless-rpc"}
	if advertise {
		args = append(args, "--advertise-refs")
	}
	args = append(args, repo)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "GIT_PROTOCOL="+gitProto)
	cmd.Stdin = stdin
	var stderr strings.Builder
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("git-upload-pack %v: %v\n%s", args, err, stderr.String())
	}
	return data
}

// newStubUpstreamServer stands up an httptest.Server that serves repo over the
// v2 smart-HTTP protocol by delegating to git-upload-pack. It is the relay's
// "stub upstream": real git produces the bytes (advertisement, refs, packfile),
// so the framing the relay pumps is ground truth, not invented. The stub serves
// one repo; the URL path is matched by suffix only.
func newStubUpstreamServer(t *testing.T, repo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gitProto := r.Header.Get("Git-Protocol")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "info/refs"):
			adv := uploadPackRepo(t, repo, true, gitProto, nil)
			// Prepend the smart-HTTP banner+flush that --advertise-refs omits
			// (git http-backend adds it; the stub replicates that). Probed
			// 2026-07-17: --advertise-refs emits the v2 advertisement with no banner.
			writePkt(w, "# service=git-upload-pack\n")
			writeFlush(w)
			w.Write(adv)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-upload-pack"):
			resp := uploadPackRepo(t, repo, false, gitProto, r.Body)
			w.Write(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// makeSourceRepo builds a work repo with one commit of real content and returns
// its path. Mirrors spike/relay-push-frame's makeRepo.
func makeSourceRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "src")
	mustRunGit(t, repo, "init", "-q", "-b", "main")
	mustRunGit(t, repo, "config", "user.email", "relay-e2e@example.invalid")
	mustRunGit(t, repo, "config", "user.name", "relay-e2e")
	if err := os.WriteFile(filepath.Join(repo, "data.txt"),
		[]byte("patvault relay slice 3 e2e\n"), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	mustRunGit(t, repo, "add", "data.txt")
	mustRunGit(t, repo, "commit", "-q", "-m", "initial")
	return repo
}

// mustRunGit runs git in dir and fails the test on error. No SSH env — for local
// repo setup only.
func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
}

// gitEnv builds the environment for driving the real git/ssh client at the
// relay. Shared by runGit (expects failure) and runGitOK (expects success).
func gitEnv(keyPath string, extra []string) []string {
	env := append(os.Environ(),
		"GIT_SSH_COMMAND=ssh -i "+keyPath+
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"+
			" -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		"GIT_TERMINAL_PROMPT=0",
	)
	return append(env, extra...)
}

// runGitOK drives the real git binary at the relay and fails the test on error.
// The mirror of runGit (which fails on success); use this for the clone/fetch
// gate where success is expected.
func runGitOK(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(keyPath, extraEnv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
```

Then refactor the existing `runGit` to use `gitEnv` too (replace its `cmd.Env = append(...)` lines with `cmd.Env = gitEnv(keyPath, extraEnv)`), so the two helpers stay in sync. The existing `runGit` body becomes:

```go
func runGit(t *testing.T, dir, keyPath string, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(keyPath, extraEnv)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %v unexpectedly succeeded:\n%s", args, out)
	}
	return string(out)
}
```

Finally, add the gate test:

```go
// The slice-3 gate. A real git clone and an incremental fetch through the relay
// backed by a git-upload-pack stub upstream must succeed end to end. This is the
// anti-drift gate: the real client, the real relay, and a real (git-backed)
// upstream exchange real v2 bytes — including a sideband-framed packfile the
// relay must pump untouched.
//
// Protocol v2 is forced via GIT_CONFIG so the test does not depend on git's
// default (the relay requires version=2 for fetch).
func TestRealGitCloneAndIncrementalFetchThroughRelay(t *testing.T) {
	requireGit(t)
	requireUploadPack(t)

	priv, signer := newE2EKey(t)
	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, priv)

	// Upstream: a bare repo seeded from a real work repo with content.
	src := makeSourceRepo(t)
	bare := filepath.Join(t.TempDir(), "e2erepo.git")
	mustRunGit(t, src, "clone", "--bare", "-q", src, bare)
	upstream := newStubUpstreamServer(t, bare)

	// Relay: real Server, real Bridge pointed at the stub upstream.
	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	s.Bridge = &Bridge{Client: upstream.Client(), BaseURL: upstream.URL}
	storePAT(t, s.OpenDB, s.Keyring, "owner/e2erepo", "ghp_stub", nil)
	addr := startRelay(t, s)

	cloneURL := "ssh://git@" + addr + "/owner/e2erepo.git"
	v2 := []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=protocol.version", "GIT_CONFIG_VALUE_0=2"}

	// 1. A real clone through the relay.
	dest := filepath.Join(t.TempDir(), "clone")
	runGitOK(t, dir, keyPath, v2, "clone", "-q", cloneURL, dest)

	// The clone must carry the commit and its content.
	mustRunGit(t, dest, "log", "--oneline", "-n1")
	got, err := os.ReadFile(filepath.Join(dest, "data.txt"))
	if err != nil {
		t.Fatalf("read cloned data.txt: %v", err)
	}
	if !bytes.Contains(got, []byte("patvault relay slice 3 e2e")) {
		t.Errorf("cloned content mismatch: %q", got)
	}
	// The PAT the relay injected upstream must never reach the client.
	if bytes.Contains(got, []byte("ghp_stub")) {
		t.Errorf("cloned content leaked the PAT: %q", got)
	}

	// 2. An incremental fetch: add a commit upstream, fetch it through the relay.
	mustRunGit(t, src, "commit", "-q", "--allow-empty", "-m", "second")
	mustRunGit(t, src, "push", "-q", bare, "main")
	runGitOK(t, dest, keyPath, v2, "fetch", "-q", "origin")
	out := runGitOK(t, dest, keyPath, v2, "log", "--oneline", "origin/main")
	if !strings.Contains(out, "second") {
		t.Errorf("incremental fetch did not bring the new commit:\n%s", out)
	}
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test -run TestRealGitCloneAndIncrementalFetchThroughRelay -v ./internal/relay/...`
Expected: PASS. If it skips with `git-upload-pack not found`, confirm `git --exec-path` resolves and the binary exists; the test is correct, the environment lacks the binary.

If the clone fails with a `patvault:` message, read it — it names the failing check (the gate is doing its job). If the clone hangs, the bridge is not half-duplex in time (re-check that `postCommand` streams the full response before `pumpCommands` loops to read the next command).

- [ ] **Step 3: Run the full suite with the race detector**

Run: `go test -race ./...`
Expected: PASS. The race detector matters here: the bridge streams concurrently with the SSH channel's read/write halves, and a data race would indicate the aliasing contract is violated.

- [ ] **Step 4: Commit**

```bash
git add internal/relay/relay_e2e_test.go
git commit -m "test(relay): real git clone + incremental fetch through the relay

Slice-3 anti-drift gate. Drives real git at a real relay backed by a
git-upload-pack stub upstream (real packfile, real sideband framing). Pins that
the fetch bridge pumps v2 bytes byte-correctly end to end, and that the injected
PAT never reaches the client.
"
```

---

## Slice gate

The slice is done when, in a clean checkout:

```bash
go build ./cmd/patvault
go vet ./...
go test ./...
go test -race ./...
```

all pass, and specifically `TestRealGitCloneAndIncrementalFetchThroughRelay` passes (not skips — `git` and `git-upload-pack` must be on PATH). That test is the implementation design's anti-drift gate for slice 3: a real `git clone` **and** a real incremental `git fetch` through the relay, against a real git-backed upstream.

## Out of scope (do not do in this slice)

- **Push bridge.** `Bridge.Push` returns a plain error; slice 4 implements the receive-pack path (`io.Copy` of commands+pack to EOF, sideband pass-through). Do not add push unit tests beyond the one in Task 2.
- **Real GitHub.** Slice 5 confirms the status→message mapping and the chunked-receive-pack assumption against the real Git endpoints. Do not add credentials or network calls.
- **Reframing, section interpretation, or pack parsing.** The bridge is a pump. Do not add code that inspects pkt-line content beyond the two advertisement packets it strips.
- **`pktline.go` writers.** Production never writes pkt-lines; `writePkt`/`writeFlush` are test helpers in `bridge_test.go`. Do not promote them to production.
