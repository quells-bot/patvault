# Relay Slice 1 — The Pure Leaves Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `internal/relay` and land its two dependency-free leaves — `pktline.go` (pkt-line length-prefix scanner) and `exec.go` (`parseExec`) — with every input pinned by a spike rather than imagined.

**Architecture:** Both files are pure functions over `io.Reader` / `string`. No SSH, no HTTP, no database, no filesystem. `pktline.go` reads framed packets and can lift one complete v2 command (framing intact, bytes unmodified) so slice 3's bridge can forward it verbatim as an HTTP body. `exec.go` shell-word splits git's exec string, allowlists the command, normalizes the path through the existing `internal/urlparse`, and shape-checks the result before any later slice interpolates it into an upstream URL.

**Tech Stack:** Go standard library only (`bytes`, `errors`, `fmt`, `io`, `regexp`, `strconv`, `strings`, `testing`), plus the existing `internal/urlparse` package.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-15-relay-design.md` is authoritative; `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` (§"Slice 1 — the pure leaves") defines this slice's scope. Do not implement anything from slices 2–5 — no `server.go`, no `bridge.go`, no `authkeys.go`, no `errors.go`, no cobra wiring.
- Go version: module targets `go 1.26.5` (from `go.mod`). Do not lower it.
- **Standard library only** — this slice adds no entries to `go.mod` / `go.sum`. In particular, do **not** add a third-party shell-words package; Task 2 writes the splitter.
- **Testing framework:** standard library `testing` only. No `testify`, no `gomock`. Table-driven tests with `{name, ...}` struct slices and `t.Run(tc.name, ...)`, per `AGENTS.md` §Testing.
- **Package:** everything lives in `internal/relay/`, `package relay`. Tests are in-package (`package relay`), matching how the repo tests unexported `run*` functions directly.
- **Visibility:** every identifier in this slice is **unexported**. Slices 2–4 live in the same package. Only the `Bridge` / `Request` seam (slice 3) is exported, and it is not this slice's job.
- **Reuse, do not reimplement:** path normalization goes through `urlparse.NormalizePath`. Do not write a second normalizer.
- Naming: `Test<FunctionName><Scenario>` — e.g. `TestParseExecRejectsUploadArchive`.
- Exported functions get doc comments; unexported helpers are self-documenting. In this slice nothing is exported, but `readPacket`, `readCommand`, `splitWords`, and `parseExec` each carry a doc comment anyway — they encode spike-pinned contracts a reader cannot infer from the body.
- Commit identity: `git config user.email noreply@anthropic.com && git config user.name Claude` before committing.
- Every commit message ends with the trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Gate for the whole slice: `go test ./internal/relay/...` passes. There is no real-`git` gate in slice 1 — that starts at slice 2, by design (implementation design §"The anti-drift rule": slice 1 has "nothing to drift against").

## What the spikes pinned (these are the plan's inputs)

Every test input below is a byte string a spike actually recorded. Do not
"improve" them from a reading of the spec — that is the exact failure mode
`docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md` §Corrections
records this project having already paid for once.

From `spike/relay-ssh/` (`docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md`
§"Exec string shape"), the four exec strings a real `git` 2.53.0 sent:

| URL path | Exec string received |
|---|---|
| `/owner/repo.git` | `git-upload-pack '/owner/repo.git'` |
| `/owner/repo` | `git-upload-pack '/owner/repo'` |
| `/owner/my repo.git` | `git-upload-pack '/owner/my repo.git'` |
| `/owner/it's.git` | `git-upload-pack '/owner/it'\''s.git'` |

and `git-receive-pack '/owner/repo.git'` for push.

Two constraints fall out, and they are why Task 2 exists at all:

1. **The path is the URL's path, verbatim.** Git neither appends nor strips
   `.git`. `parseExec` must accept both forms because the *user's remote URL*
   may or may not carry the suffix.
2. **The quoting is POSIX shell quoting, not "wrapped in quotes".** The
   apostrophe case arrives as `'/owner/it'\''s.git'` — close-quote, escaped
   quote, reopen-quote. Stripping the first and last quote yields
   `/owner/it'\''s.git`, which is **wrong**. The base spec's §"Exec parsing"
   hazard 1 ("strip one level of shell quoting rather than naive
   whitespace-splitting") is the correct instruction; hazard 3's opening words
   ("Strip the surrounding quotes") describe the naive parse that gets this case
   wrong. The findings note flags this tension explicitly. **Follow hazard 1.**

From `spike/relay-v2/pktline.go`, which the v2 spike's README names as the
reference for `internal/relay/pktline.go`: the length-prefix scanner shape,
including the `0000` / `0001` / reserved-`0002`,`0003` / 65520-maximum rules.

## File Structure

| Path | Responsibility |
|---|---|
| `internal/relay/pktline.go` | `readPacket` (one pkt-line, length prefix stripped) and `readCommand` (one complete v2 command, framing intact). Nothing else — no writers (see below), no `# service=` strip (that is `bridge.go`'s, per the base spec's module table). |
| `internal/relay/pktline_test.go` | Both, against hand-built byte strings. |
| `internal/relay/exec.go` | `splitWords` (POSIX shell-word splitter) and `parseExec` (allowlist + normalize + shape check). |
| `internal/relay/exec_test.go` | Both, driven by the spike-recorded exec strings above. |

**No pkt-line writers.** `spike/relay-v2/pktline.go` has `writePktLine` /
`writeFlush` / `writeDelim` because the spike *was* a client and had to
construct commands. The relay never constructs a pkt-line: it forwards the
client's bytes and, on failure, writes plain text to stderr (base spec
§"Errors": "Error surface: stderr + `exit-status`, never stdout"). Slices 3–4's
stub upstream replays spike-recorded bytes. YAGNI — do not port the writers.

---

### Task 1: `readPacket` — the length-prefix scanner

**Files:**
- Create: `internal/relay/pktline.go`
- Test: `internal/relay/pktline_test.go`

**Interfaces:**
- Consumes: nothing from other tasks. This is the first file in the package.
- Produces:
  ```go
  const (
      pktData  = iota // a normal data packet
      pktFlush        // flush-pkt: "0000"
      pktDelim        // delim-pkt: "0001"
  )
  const maxPktLine = 65520

  func readPacket(r io.Reader) (payload []byte, kind int, err error)
  ```
  `readPacket` returns a **bare `io.EOF`** (not wrapped) when `r` is exhausted
  at a clean packet boundary — Task 2 depends on `errors.Is(err, io.EOF)`
  distinguishing "the peer is done" from "the stream was cut mid-packet".

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/pktline_test.go`:

```go
package relay

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadPacketData(t *testing.T) {
	r := strings.NewReader("0014command=ls-refs\n")
	payload, kind, err := readPacket(r)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if kind != pktData {
		t.Errorf("kind = %d, want pktData", kind)
	}
	if string(payload) != "command=ls-refs\n" {
		t.Errorf("payload = %q, want %q", payload, "command=ls-refs\n")
	}
}

func TestReadPacketFlushAndDelim(t *testing.T) {
	r := strings.NewReader("00000001")

	if _, kind, err := readPacket(r); err != nil || kind != pktFlush {
		t.Fatalf("first packet: kind=%d err=%v, want pktFlush", kind, err)
	}
	if _, kind, err := readPacket(r); err != nil || kind != pktDelim {
		t.Fatalf("second packet: kind=%d err=%v, want pktDelim", kind, err)
	}
}

func TestReadPacketSequence(t *testing.T) {
	// One ls-refs command as spike/relay-v2 framed it: command, capabilities,
	// delim, arguments, flush.
	r := strings.NewReader(
		"0014command=ls-refs\n" +
			"0017object-format=sha1\n" +
			"0001" +
			"0009peel\n" +
			"0000")

	want := []struct {
		payload string
		kind    int
	}{
		{"command=ls-refs\n", pktData},
		{"object-format=sha1\n", pktData},
		{"", pktDelim},
		{"peel\n", pktData},
		{"", pktFlush},
	}
	for i, w := range want {
		payload, kind, err := readPacket(r)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if kind != w.kind {
			t.Errorf("packet %d: kind = %d, want %d", i, kind, w.kind)
		}
		if string(payload) != w.payload {
			t.Errorf("packet %d: payload = %q, want %q", i, payload, w.payload)
		}
	}
	if _, _, err := readPacket(r); !errors.Is(err, io.EOF) {
		t.Errorf("after last packet: err = %v, want io.EOF", err)
	}
}

// A bare io.EOF at a packet boundary is the "peer is done" signal readCommand
// keys on; it must not arrive wrapped.
func TestReadPacketCleanEOF(t *testing.T) {
	_, _, err := readPacket(strings.NewReader(""))
	if err != io.EOF {
		t.Errorf("err = %v, want exactly io.EOF", err)
	}
}

func TestReadPacketErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"non-hex length", "zzzz"},
		{"reserved length 2", "0002"},
		{"reserved length 3", "0003"},
		{"truncated prefix", "00"},
		{"truncated body", "0014command"},
		{"length over maximum", "fff1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readPacket(strings.NewReader(tc.in)); err == nil {
				t.Errorf("readPacket(%q) = nil error, want error", tc.in)
			}
		})
	}
}

// A truncated stream must never masquerade as a clean end of stream.
func TestReadPacketTruncatedIsNotEOF(t *testing.T) {
	_, _, err := readPacket(bytes.NewReader([]byte("00")))
	if errors.Is(err, io.EOF) {
		t.Errorf("truncated prefix reported as EOF: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL — the package does not exist yet
(`no required module provides package .../internal/relay` or, once the directory
exists, `undefined: readPacket`).

- [ ] **Step 3: Write the implementation**

Create `internal/relay/pktline.go`:

```go
// Package relay implements patvault's credential-injecting git transport
// relay: an SSH front door for the agent's git, bridged to GitHub over HTTPS
// with a stored PAT injected upstream.
package relay

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// pkt-line kinds returned by readPacket.
const (
	pktData  = iota // a normal data packet
	pktFlush        // flush-pkt: "0000"
	pktDelim        // delim-pkt: "0001"
)

// maxPktLine is the largest a pkt-line may be, 4-byte length prefix included.
const maxPktLine = 65520

// readPacket reads one pkt-line from r. Flush and delim packets return a nil
// payload with kind pktFlush or pktDelim; a data packet returns its payload
// with the length prefix stripped.
//
// A clean end of stream at a packet boundary returns a bare io.EOF. Every
// other failure — including a stream cut part-way through a packet — returns a
// wrapped error, so callers can tell "the peer is done" from "the peer is
// gone".
func readPacket(r io.Reader) (payload []byte, kind int, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, fmt.Errorf("truncated pkt-line length prefix: %w", err)
		}
		return nil, 0, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pkt-line length %q", hdr[:])
	}
	switch n {
	case 0:
		return nil, pktFlush, nil
	case 1:
		return nil, pktDelim, nil
	case 2, 3:
		return nil, 0, fmt.Errorf("reserved pkt-line length %d", n)
	}
	if n > maxPktLine {
		return nil, 0, fmt.Errorf("pkt-line length %d exceeds maximum %d", n, maxPktLine)
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, 0, fmt.Errorf("short pkt-line body (want %d bytes): %w", n-4, err)
	}
	return buf, pktData, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS (`ok  github.com/quells-bot/patvault/internal/relay`).

Also run: `go vet ./internal/relay/...`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/pktline.go internal/relay/pktline_test.go
git commit -m "$(cat <<'EOF'
feat: pkt-line length-prefix scanner for the relay

Slice 1 of the relay implementation (see the slicing design): the pure leaves,
no I/O and nothing to drift against.

readPacket is spike/relay-v2/pktline.go's reader, which that spike's README
names as the reference for this file. The writers are deliberately not ported:
the spike was a client and had to construct commands, whereas the relay only
ever forwards the client's bytes and reports errors as plain text on stderr.

The one contract worth stating: a clean EOF at a packet boundary comes back as
a bare io.EOF, while a stream cut mid-packet comes back wrapped. The command
reader needs to tell "the peer is done" from "the peer is gone".

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `readCommand` — one complete v2 command, bytes untouched

The base spec's §"Relay → GitHub" step 2 describes slice 3's fetch pump: "read
one client command from the SSH channel up to its terminating flush-pkt (v2
commands like `ls-refs` and `fetch` are self-contained), `POST
.../git-upload-pack` … with that body". This task is that read. It returns the
**raw bytes including framing**, because the body is forwarded verbatim — which
is also what makes partial clone (`filter=blob:none`) and shallow clone
(`depth`) work for free.

An interior **delim-pkt does not terminate a command** — a v2 command is
`command=…`, capabilities, `0001`, arguments, `0000`. Only the flush ends it.

**Files:**
- Modify: `internal/relay/pktline.go`
- Test: `internal/relay/pktline_test.go`

**Interfaces:**
- Consumes: `readPacket`, `pktFlush`, and the bare-`io.EOF` contract from Task 1.
- Produces:
  ```go
  func readCommand(r io.Reader) ([]byte, error)
  ```
  Returns `io.EOF` with no bytes when `r` is already at end of stream — slice
  3's pump loop terminates on this ("repeat until the client sends no more
  (channel EOF)"). Returns `io.ErrUnexpectedEOF` when the stream ends after a
  whole packet but before a flush.

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/pktline_test.go`:

```go
func TestReadCommandRoundTripsBytesVerbatim(t *testing.T) {
	// The ls-refs command spike/relay-v2/main.go sends, byte for byte. The
	// bridge forwards this as an HTTP body unmodified, so the returned bytes
	// must equal the input exactly — framing, interior delim, and all.
	const cmd = "0014command=ls-refs\n" +
		"0017object-format=sha1\n" +
		"0001" +
		"0009peel\n" +
		"000csymrefs\n" +
		"0014ref-prefix HEAD\n" +
		"0000"

	got, err := readCommand(strings.NewReader(cmd))
	if err != nil {
		t.Fatalf("readCommand: %v", err)
	}
	if string(got) != cmd {
		t.Errorf("readCommand returned\n%q\nwant\n%q", got, cmd)
	}
}

func TestReadCommandStopsAtFirstFlush(t *testing.T) {
	const first = "0014command=ls-refs\n0000"
	const second = "0012command=fetch\n0000"
	r := strings.NewReader(first + second)

	got, err := readCommand(r)
	if err != nil {
		t.Fatalf("first readCommand: %v", err)
	}
	if string(got) != first {
		t.Errorf("first command = %q, want %q", got, first)
	}

	got, err = readCommand(r)
	if err != nil {
		t.Fatalf("second readCommand: %v", err)
	}
	if string(got) != second {
		t.Errorf("second command = %q, want %q", got, second)
	}

	if _, err := readCommand(r); !errors.Is(err, io.EOF) {
		t.Errorf("third readCommand: err = %v, want io.EOF", err)
	}
}

// The pump loop's termination condition: no more commands is io.EOF, not an
// error and not an empty command.
func TestReadCommandCleanEOF(t *testing.T) {
	got, err := readCommand(strings.NewReader(""))
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if len(got) != 0 {
		t.Errorf("returned %q, want no bytes", got)
	}
}

func TestReadCommandTruncated(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"whole packet then EOF, no flush", "0014command=ls-refs\n", io.ErrUnexpectedEOF},
		{"packet cut mid-body", "0014command", nil}, // some error, not EOF
		{"invalid length", "0014command=ls-refs\nzzzz", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readCommand(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("readCommand(%q) = nil error, want error", tc.in)
			}
			if errors.Is(err, io.EOF) {
				t.Errorf("truncated input reported as clean EOF: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: readCommand`.

- [ ] **Step 3: Write the implementation**

Add to `internal/relay/pktline.go` — and add `"bytes"` to its imports:

```go
// readCommand reads one complete protocol-v2 command from r: every byte from
// its first pkt-line through its terminating flush-pkt, framing intact and
// unmodified, ready to be forwarded verbatim as an HTTP request body. An
// interior delim-pkt does not terminate a command.
//
// It returns io.EOF, and no bytes, when r is already at end of stream — the
// client has no more commands, which is how the fetch pump's loop ends. A
// stream that ends after a whole packet but before a flush is a truncation,
// reported as io.ErrUnexpectedEOF.
func readCommand(r io.Reader) ([]byte, error) {
	// The tee is what keeps the bytes verbatim: readPacket parses from it
	// while every byte it consumes accumulates in raw, so nothing is
	// re-encoded on the way out.
	var raw bytes.Buffer
	tee := io.TeeReader(r, &raw)

	for {
		_, kind, err := readPacket(tee)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if raw.Len() == 0 {
					return nil, io.EOF
				}
				return nil, fmt.Errorf("stream ended before flush-pkt: %w", io.ErrUnexpectedEOF)
			}
			return nil, err
		}
		if kind == pktFlush {
			return raw.Bytes(), nil
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Then confirm the whole suite is still green: `go test ./...`
Expected: PASS for every package.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/pktline.go internal/relay/pktline_test.go
git commit -m "$(cat <<'EOF'
feat: read one v2 command up to its terminating flush

The read half of slice 3's fetch pump, landed early because it is pure: one
self-contained v2 command in, one HTTP request body out.

Returns the raw bytes with framing intact rather than re-encoding them. The
bridge forwards the body verbatim -- that is what makes partial and shallow
clone work for free -- so an io.TeeReader captures what readPacket consumes
instead of the parse being reversed on the way out.

Two boundaries the pump depends on: an interior delim-pkt does not end a
command (a v2 command is command=, caps, 0001, args, 0000), and a clean EOF
means the client has no more commands, whereas an EOF before the flush is a
truncation and says so.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `splitWords` — a POSIX shell-word splitter

This task exists because of one spike-recorded byte string:
`git-upload-pack '/owner/it'\''s.git'`. Git quotes the path with its `sq_quote`,
which renders an apostrophe as `'\''` — close-quote, escaped quote,
reopen-quote. Stripping the first and last quote yields `/owner/it'\''s.git`.
The findings note calls this out as the thing a naive parse gets wrong, and the
base spec's hazard 1 already says to split rather than strip.

Standard library only — do not add a shell-words dependency for ~45 lines.

**gofmt hazard, verified — do not "clean up" the doc comment below.** gofmt's
doc-comment formatter converts a pair of adjacent apostrophes into a
typographic `”`. Written as flowing prose, the comment's own `'\''` — the exact
byte string it exists to record — is silently rewritten to `'\”` on the first
`gofmt -w`, and `gofmt -l` will keep reporting the file until it is. Both
examples therefore sit in indented code blocks, which the formatter leaves
alone. This was reproduced against Go 1.26.5 while writing this plan.

**Files:**
- Modify: `internal/relay/exec.go` (create it in this task)
- Test: `internal/relay/exec_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  func splitWords(s string) ([]string, error)
  ```
  Splits on unquoted whitespace, honoring single quotes (everything literal),
  double quotes (backslash escapes `"`, `\`, `$`, and backtick only), and
  backslash escapes outside quotes. Adjacent quoted and unquoted runs
  concatenate into one word. An unterminated quote or a trailing backslash is
  an error.

- [ ] **Step 1: Write the failing tests**

Create `internal/relay/exec_test.go`. Note the backtick-quoted Go strings: the
apostrophe case contains a literal backslash, so a double-quoted Go string
would need escaping and would no longer be the recorded bytes.

```go
package relay

import (
	"slices"
	"testing"
)

func TestSplitWords(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		// The four exec strings spike/relay-ssh recorded from git 2.53.0.
		{
			name: "suffixed path",
			in:   `git-upload-pack '/owner/repo.git'`,
			want: []string{"git-upload-pack", "/owner/repo.git"},
		},
		{
			name: "unsuffixed path",
			in:   `git-upload-pack '/owner/repo'`,
			want: []string{"git-upload-pack", "/owner/repo"},
		},
		{
			name: "space survives inside quotes",
			in:   `git-upload-pack '/owner/my repo.git'`,
			want: []string{"git-upload-pack", "/owner/my repo.git"},
		},
		{
			// The case a first-and-last-quote strip gets wrong: it would
			// yield /owner/it'\''s.git.
			name: "apostrophe is POSIX-escaped",
			in:   `git-upload-pack '/owner/it'\''s.git'`,
			want: []string{"git-upload-pack", "/owner/it's.git"},
		},
		{
			name: "push exec",
			in:   `git-receive-pack '/owner/repo.git'`,
			want: []string{"git-receive-pack", "/owner/repo.git"},
		},

		{name: "unquoted", in: `git-upload-pack /owner/repo`, want: []string{"git-upload-pack", "/owner/repo"}},
		{name: "runs of whitespace", in: "  a \t\t b  ", want: []string{"a", "b"}},
		{name: "empty", in: ``, want: nil},
		{name: "only whitespace", in: `   `, want: nil},
		{name: "empty quoted word", in: `a '' b`, want: []string{"a", "", "b"}},
		{name: "double quotes", in: `a "b c"`, want: []string{"a", "b c"}},
		{name: "escape inside double quotes", in: `a "b\"c"`, want: []string{"a", `b"c`}},
		{name: "non-escape inside double quotes", in: `a "b\nc"`, want: []string{"a", `b\nc`}},
		{name: "backslash escape outside quotes", in: `a b\ c`, want: []string{"a", "b c"}},
		{name: "adjacent runs concatenate", in: `pre'mid'post`, want: []string{"premidpost"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitWords(tc.in)
			if err != nil {
				t.Fatalf("splitWords(%q): %v", tc.in, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("splitWords(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSplitWordsErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"unterminated single quote", `git-upload-pack '/owner/repo`},
		{"unterminated double quote", `git-upload-pack "/owner/repo`},
		{"trailing backslash", `git-upload-pack /owner/repo\`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := splitWords(tc.in); err == nil {
				t.Errorf("splitWords(%q) = nil error, want error", tc.in)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: splitWords`.

- [ ] **Step 3: Write the implementation**

Create `internal/relay/exec.go`:

```go
package relay

import (
	"errors"
	"strings"
)

// dqEscapable is the set of characters a backslash escapes inside double
// quotes. Anywhere else inside them a backslash is a literal backslash.
const dqEscapable = "\"\\$`"

// splitWords splits s into words the way a POSIX shell would: on unquoted
// whitespace, honoring single quotes, double quotes, and backslash escapes,
// with adjacent quoted and unquoted runs concatenating into one word.
//
// Git quotes the repository path with sq_quote, which renders an apostrophe as
// close-quote, escaped quote, reopen-quote. A real git sent this exec string,
// and it carries one path — /owner/it's.git:
//
//	git-upload-pack '/owner/it'\''s.git'
//
// That is why this splits rather than stripping the first and last quote,
// which would mangle that path into:
//
//	/owner/it'\''s.git
func splitWords(s string) ([]string, error) {
	var (
		words  []string
		cur    []rune
		inWord bool
	)
	rs := []rune(s)

	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, string(cur))
				cur, inWord = nil, false
			}

		case c == '\'':
			inWord = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				cur = append(cur, rs[j])
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unterminated single quote")
			}
			i = j

		case c == '"':
			inWord = true
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune(dqEscapable, rs[j+1]) {
					j++
				}
				cur = append(cur, rs[j])
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unterminated double quote")
			}
			i = j

		case c == '\\':
			if i+1 == len(rs) {
				return nil, errors.New("trailing backslash")
			}
			inWord = true
			i++
			cur = append(cur, rs[i])

		default:
			inWord = true
			cur = append(cur, c)
		}
	}
	if inWord {
		words = append(words, string(cur))
	}
	return words, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Also run: `go vet ./internal/relay/...`
Expected: no output.

Then the gofmt check, which matters here specifically (see the hazard above):

Run: `gofmt -l internal/relay`
Expected: no output. If `exec.go` is listed, run `gofmt -d internal/relay/exec.go`
and check what it wants to change — if it is rewriting `'\''` inside the
`splitWords` doc comment, the example has escaped its indented code block. Put
it back rather than accepting the reformat.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/exec.go internal/relay/exec_test.go
git commit -m "$(cat <<'EOF'
feat: POSIX shell-word splitter for relay exec strings

Exists because of one byte string the relay-ssh spike recorded:

    git-upload-pack '/owner/it'\''s.git'

git quotes the path with sq_quote, so an apostrophe comes back as close-quote,
escaped quote, reopen-quote. Stripping the first and last quote yields
/owner/it'\''s.git -- the spec's exec-parsing hazard 1 says split rather than
strip, and this is why. The test drives all four exec strings the spike pinned
verbatim, in backticks so the recorded backslash stays a backslash.

Hand-written rather than a dependency: it is ~45 lines and the module has no
third-party parsing deps.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `parseExec` — allowlist, normalize, shape-check

The base spec's §"Exec parsing" in full, minus the splitting Task 3 did:
command allowlist (with `git-upload-archive` explicitly rejected — it would
expose `git archive --remote`), leading-`/` strip, `urlparse.NormalizePath`,
and the `owner/repo` shape check that runs "before the value is ever
interpolated into an upstream URL".

**Files:**
- Modify: `internal/relay/exec.go`
- Test: `internal/relay/exec_test.go`

**Interfaces:**
- Consumes: `splitWords` from Task 3; `urlparse.NormalizePath` from the
  existing `internal/urlparse` package (strips one trailing `.git` and trailing
  slashes; preserves case).
- Produces:
  ```go
  const (
      opFetch = "git-upload-pack"  // read: clone/fetch
      opPush  = "git-receive-pack" // write: push
  )

  func parseExec(cmd string) (op, repo string, err error)
  ```
  `op` is `opFetch` or `opPush`; `repo` is a normalized, shape-checked
  `owner/repo`. **Every** error is the same condition to slice 2's `errors.go`:
  the disallowed-exec row — `patvault: only git fetch/push are permitted`,
  exit **128**. The distinct error texts are for the host-side operational log,
  not for the client. Slice 2 does **not** need to discriminate them, so this
  task defines no sentinel errors.

**A note on the shape check's strictness.** The base spec's hazard 4 says
"exactly `owner/repo` (two non-empty segments, no `..`, no extra slashes)". A
literal reading of that would *accept* `owner/my repo` and `owner/it's` — but
the relay-ssh findings note states the shape check "rejects them regardless"
because "GitHub allows only alphanumerics, `-`, `_`, `.`". This plan implements
the note's reading: a character-class check, not just a segment count. It is
the stricter of the two, it is what makes the note's claim true, and hazard 4's
own stated purpose ("defense against path-traversal / SSRF-ish input") argues
for allowlisting characters rather than blocklisting `..`. Consequence: a repo
name outside GitHub's character set is a false rejection rather than a bad
upstream URL.

- [ ] **Step 1: Write the failing tests**

Append to `internal/relay/exec_test.go`:

```go
func TestParseExecAccepts(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantOp   string
		wantRepo string
	}{
		// Spike-recorded shapes.
		{"fetch, suffixed", `git-upload-pack '/owner/repo.git'`, opFetch, "owner/repo"},
		{"fetch, unsuffixed", `git-upload-pack '/owner/repo'`, opFetch, "owner/repo"},
		{"push, suffixed", `git-receive-pack '/owner/repo.git'`, opPush, "owner/repo"},

		// The spec's other legitimate inputs: git echoes the user's remote
		// URL path, so any of these can arrive.
		{"no leading slash", `git-upload-pack 'owner/repo'`, opFetch, "owner/repo"},
		{"trailing slash", `git-upload-pack '/owner/repo/'`, opFetch, "owner/repo"},
		{"suffix and trailing slash", `git-upload-pack '/owner/repo.git/'`, opFetch, "owner/repo"},
		{"unquoted", `git-upload-pack /owner/repo.git`, opFetch, "owner/repo"},

		{"case is preserved", `git-upload-pack '/Owner/Repo.git'`, opFetch, "Owner/Repo"},
		{"hyphens, underscores, dots", `git-upload-pack '/my-org/my_repo.js.git'`, opFetch, "my-org/my_repo.js"},
		{"digits", `git-upload-pack '/owner2/repo2.git'`, opFetch, "owner2/repo2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, repo, err := parseExec(tc.in)
			if err != nil {
				t.Fatalf("parseExec(%q): %v", tc.in, err)
			}
			if op != tc.wantOp {
				t.Errorf("op = %q, want %q", op, tc.wantOp)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tc.wantRepo)
			}
		})
	}
}

func TestParseExecRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		// Command allowlist. git-upload-archive is rejected on purpose: it
		// would expose git archive --remote through the relay.
		{"upload-archive", `git-upload-archive '/owner/repo.git'`},
		{"shell", ``},
		{"shell command", `bash -c 'id'`},
		{"bare binary", `sh`},
		{"space form, not the hyphen form git sends", `git upload-pack '/owner/repo'`},
		{"unknown command", `scp -t /tmp/x`},
		{"no path", `git-upload-pack`},
		{"extra argument", `git-upload-pack '/owner/repo' --stateless-rpc`},

		// Shape check.
		{"traversal", `git-upload-pack '/../../etc/passwd'`},
		{"traversal inside", `git-upload-pack '/owner/../../etc'`},
		{"extra segments", `git-upload-pack '/owner/repo/extra'`},
		{"single segment", `git-upload-pack '/repo.git'`},
		{"empty owner", `git-upload-pack '//repo.git'`},
		{"empty path", `git-upload-pack ''`},
		{"dot repo", `git-upload-pack '/owner/.'`},
		{"dotdot repo", `git-upload-pack '/owner/..'`},

		// Not GitHub repo names; the last two are the spike-recorded paths
		// whose quoting Task 3 pins.
		{"space in name", `git-upload-pack '/owner/my repo.git'`},
		{"apostrophe in name", `git-upload-pack '/owner/it'\''s.git'`},
		{"query string", `git-upload-pack '/owner/repo?x=1'`},
		{"host injection", `git-upload-pack '/owner/repo@evil.example'`},
		{"colon in name", `git-upload-pack '/owner/repo:x'`},

		// Unparseable.
		{"unterminated quote", `git-upload-pack '/owner/repo`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, repo, err := parseExec(tc.in)
			if err == nil {
				t.Fatalf("parseExec(%q) = (%q, %q, nil), want error", tc.in, op, repo)
			}
			if op != "" || repo != "" {
				t.Errorf("on error got (%q, %q), want empty strings", op, repo)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL with `undefined: parseExec`, `undefined: opFetch`, `undefined: opPush`.

- [ ] **Step 3: Write the implementation**

Add to `internal/relay/exec.go` — its import block becomes:

```go
import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/quells-bot/patvault/internal/urlparse"
)
```

and append:

```go
// The only two operations the relay serves. These are the hyphenated forms git
// the client always sends over SSH. git-upload-archive is deliberately absent:
// relaying it would expose git archive --remote.
const (
	opFetch = "git-upload-pack"  // read: clone/fetch
	opPush  = "git-receive-pack" // write: push
)

// GitHub's spelling of the two segments: a login is alphanumerics and interior
// hyphens; a repository name adds underscores and dots.
var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// parseExec parses the exec request git sends as its transport command — e.g.
// git-upload-pack '/owner/repo.git' — into the operation and the normalized
// owner/repo it names.
//
// Every error it returns is one condition to the caller: the disallowed-exec
// refusal. The distinctions between them are for the host-side log.
func parseExec(cmd string) (op, repo string, err error) {
	words, err := splitWords(cmd)
	if err != nil {
		return "", "", fmt.Errorf("unparseable exec %q: %w", cmd, err)
	}
	if len(words) != 2 {
		return "", "", fmt.Errorf("exec must be one command and one path, got %d words", len(words))
	}

	op = words[0]
	if op != opFetch && op != opPush {
		return "", "", fmt.Errorf("disallowed command %q", op)
	}

	// The path is the URL's path verbatim — git neither adds nor strips the
	// .git suffix, so both forms arrive and both must resolve to the stored
	// (github.com, owner/repo) key.
	repo = urlparse.NormalizePath(strings.TrimPrefix(words[1], "/"))
	if err := checkRepoShape(repo); err != nil {
		return "", "", fmt.Errorf("bad repository path %q: %w", words[1], err)
	}
	return op, repo, nil
}

// checkRepoShape requires exactly owner/repo, both segments spelled the way
// GitHub spells them. It runs before the value reaches an upstream URL, so
// anything it does not recognize is refused rather than guessed at.
func checkRepoShape(repo string) error {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return errors.New("expected owner/repo")
	}
	if strings.Contains(name, "/") {
		return errors.New("expected owner/repo, got extra path segments")
	}
	if !ownerPattern.MatchString(owner) {
		return fmt.Errorf("invalid owner %q", owner)
	}
	if name == "." || name == ".." || !repoPattern.MatchString(name) {
		return fmt.Errorf("invalid repository name %q", name)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS.

Then the slice gate — the whole suite, with the race detector, uncached:

Run: `go test -race -count=1 ./...`
Expected: PASS for every package, including `internal/relay`.

Run: `go vet ./...`
Expected: no output.

Run: `gofmt -l internal/relay`
Expected: no output (no file needs formatting).

- [ ] **Step 5: Commit**

```bash
git add internal/relay/exec.go internal/relay/exec_test.go
git commit -m "$(cat <<'EOF'
feat: parseExec — command allowlist, path normalization, shape check

Completes slice 1 of the relay: internal/relay now has both pure leaves and no
I/O of any kind. Slice 2 adds the SSH front door on top.

Allowlists git-upload-pack and git-receive-pack and nothing else --
git-upload-archive is rejected on purpose, since relaying it would expose
git archive --remote. Path handling reuses urlparse.NormalizePath rather than
growing a second normalizer, so '/owner/repo.git', 'owner/repo' and
'/owner/repo/' all resolve to the same stored key.

The shape check follows the relay-ssh findings note rather than the spec's
hazard 4 literally: it allowlists GitHub's character set instead of only
counting segments and blocklisting "..". The note asserts the check rejects
'/owner/my repo.git' and '/owner/it'\''s.git', which a segment count alone
would admit, and hazard 4's own purpose -- defense before the value reaches an
upstream URL -- argues for an allowlist. The cost is a false rejection for a
name outside that set.

No sentinel errors: every failure here maps to the same row of the spec's error
table (only git fetch/push are permitted, exit 128). The distinct texts are for
the host-side log.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Slice gate

Slice 1 is done when:

- `go test -race -count=1 ./...` passes.
- `go vet ./...` is silent and `gofmt -l internal/relay` is empty.
- `internal/relay` contains exactly `pktline.go`, `pktline_test.go`, `exec.go`,
  `exec_test.go` — and imports nothing outside the standard library plus
  `internal/urlparse`. Verify: `go list -deps ./internal/relay | grep patvault`
  should print only `.../internal/urlparse` and `.../internal/relay`.
- `go.mod` and `go.sum` are unchanged: `git diff --exit-code go.mod go.sum`.

Per the implementation design's slicing table, slice 1's gate is `go test`
alone. The real-`git` gate begins at slice 2, where the SSH front door exists to
drive.

## Out of scope (do not build these here)

- `server.go`, `authkeys.go`, `errors.go`, `commands/relay.go` — **slice 2**.
  In particular the `GIT_PROTOCOL == "version=2"` gate is slice 2's; slice 1
  never sees an env request.
- `bridge.go`, the `Bridge` / `Request` seam, the `# service=` banner strip, PAT
  injection — **slices 3–4**.
- pkt-line writers — the relay never constructs a pkt-line. See §File Structure.
