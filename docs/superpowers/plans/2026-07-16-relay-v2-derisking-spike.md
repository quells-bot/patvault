# Relay v2 Protocol De-Risking Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove — against real GitHub — that patvault's relay can drive a git wire-protocol-v2 fetch over smart-HTTP by injecting a PAT, before any relay/SSH code is written.

**Architecture:** A throwaway standalone Go program (`package main` under `spike/relay-v2/`) that speaks GitHub's smart-HTTP v2 protocol directly: a `GET .../info/refs?service=git-upload-pack` advertisement probe, then two POSTs (`ls-refs`, then `fetch`) hand-framed as pkt-lines with `Authorization: Bearer <PAT>` and `Git-Protocol: version=2`. Pkt-line framing lives in a small helper with real unit tests; the network checks hard-assert protocol expectations and exit non-zero on any failure, so running the program is itself the pass/fail gate. The pkt-line helper is written to directly inform the eventual `internal/relay/pktline.go`.

**Tech Stack:** Go standard library only (`net/http`, `bytes`, `io`, `strconv`, `strings`, `os`, `fmt`). No new module dependencies.

## Global Constraints

- Go version: module targets `go 1.26.5` (from `go.mod`). Do not lower it.
- **Standard library only** — the spike adds no entries to `go.mod`/`go.sum`.
- Spike code lives under `spike/relay-v2/` as `package main`; it is explicitly throwaway and separate from `cmd/` and `internal/`.
- The spike hits **real GitHub** and requires live credentials supplied at run time via environment variables — it cannot run in CI. `SPIKE_REPO=owner/repo` and `SPIKE_TOKEN=<fine-grained PAT>` are required; the token must have Contents access to `SPIKE_REPO`. Use a **private** repo so the no-auth check is meaningful (or set `SPIKE_PUBLIC=1` to skip that one check).
- Never hardcode a token or repo in source or commit messages; they come from the environment only.
- Commit identity: `git config user.email noreply@anthropic.com && git config user.name Claude` before committing.

---

### Task 1: Pkt-line framing helpers (pure, unit-tested)

The one piece of the spike that is deterministic and testable offline: encode and decode git pkt-lines. This mirrors what `internal/relay/pktline.go` will later formalize.

**Files:**
- Create: `spike/relay-v2/pktline.go`
- Test: `spike/relay-v2/pktline_test.go`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces:
  - `const ( pktData = iota; pktFlush; pktDelim )`
  - `func writePktLine(w io.Writer, payload string) error`
  - `func writeFlush(w io.Writer) error`
  - `func writeDelim(w io.Writer) error`
  - `func readPktLine(r io.Reader) (payload []byte, kind int, err error)` — `kind` is one of the `pkt*` constants; `payload` is nil for flush/delim.

- [ ] **Step 1: Write the failing tests**

Create `spike/relay-v2/pktline_test.go`:

```go
package main

import (
	"bytes"
	"testing"
)

func TestWritePktLineKnownVector(t *testing.T) {
	var buf bytes.Buffer
	if err := writePktLine(&buf, "hello\n"); err != nil {
		t.Fatal(err)
	}
	// len("hello\n")=6, +4 prefix = 10 = 0x0a
	if got, want := buf.String(), "000ahello\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriteDoneVector(t *testing.T) {
	var buf bytes.Buffer
	if err := writePktLine(&buf, "done\n"); err != nil {
		t.Fatal(err)
	}
	// len("done\n")=5, +4 = 9 = 0x09
	if got, want := buf.String(), "0009done\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFlushAndDelim(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFlush(&buf); err != nil {
		t.Fatal(err)
	}
	if err := writeDelim(&buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "00000001"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	writePktLine(&buf, "command=ls-refs\n")
	writeDelim(&buf)
	writePktLine(&buf, "peel\n")
	writeFlush(&buf)

	p, kind, err := readPktLine(&buf)
	if err != nil || kind != pktData || string(p) != "command=ls-refs\n" {
		t.Fatalf("pkt1: p=%q kind=%d err=%v", p, kind, err)
	}
	if _, kind, err = readPktLine(&buf); err != nil || kind != pktDelim {
		t.Fatalf("pkt2: kind=%d err=%v", kind, err)
	}
	p, kind, err = readPktLine(&buf)
	if err != nil || kind != pktData || string(p) != "peel\n" {
		t.Fatalf("pkt3: p=%q kind=%d err=%v", p, kind, err)
	}
	if _, kind, err = readPktLine(&buf); err != nil || kind != pktFlush {
		t.Fatalf("pkt4: kind=%d err=%v", kind, err)
	}
}

func TestReadInvalidLength(t *testing.T) {
	if _, _, err := readPktLine(bytes.NewReader([]byte("zzzz"))); err == nil {
		t.Fatal("expected error on invalid hex length")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./spike/relay-v2/`
Expected: FAIL — compile error, `undefined: writePktLine` (and the other symbols).

- [ ] **Step 3: Implement the helpers**

Create `spike/relay-v2/pktline.go`:

```go
package main

import (
	"fmt"
	"io"
	"strconv"
)

// pkt-line kinds returned by readPktLine.
const (
	pktData  = iota // a normal data packet
	pktFlush        // flush-pkt: "0000"
	pktDelim        // delim-pkt: "0001"
)

// writePktLine writes payload as one pkt-line: a 4-byte hex length prefix
// covering the whole line (prefix + payload) followed by the payload.
func writePktLine(w io.Writer, payload string) error {
	n := len(payload) + 4
	if n > 65520 {
		return fmt.Errorf("pkt-line payload too long: %d bytes", len(payload))
	}
	_, err := fmt.Fprintf(w, "%04x%s", n, payload)
	return err
}

// writeFlush writes a flush-pkt ("0000").
func writeFlush(w io.Writer) error {
	_, err := io.WriteString(w, "0000")
	return err
}

// writeDelim writes a delim-pkt ("0001").
func writeDelim(w io.Writer) error {
	_, err := io.WriteString(w, "0001")
	return err
}

// readPktLine reads one pkt-line. For flush/delim packets it returns a nil
// payload with kind pktFlush/pktDelim. For data packets it returns the payload
// (length prefix stripped) with kind pktData.
func readPktLine(r io.Reader) (payload []byte, kind int, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pkt-line length %q: %w", hdr[:], err)
	}
	switch n {
	case 0:
		return nil, pktFlush, nil
	case 1:
		return nil, pktDelim, nil
	case 2, 3:
		return nil, 0, fmt.Errorf("reserved pkt-line length %d", n)
	}
	buf := make([]byte, n-4)
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, 0, fmt.Errorf("short pkt-line body (want %d bytes): %w", n-4, err)
	}
	return buf, pktData, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./spike/relay-v2/`
Expected: PASS (`ok  github.com/quells-bot/patvault/spike/relay-v2`).

- [ ] **Step 5: Commit**

```bash
git config user.email noreply@anthropic.com && git config user.name Claude
git add spike/relay-v2/pktline.go spike/relay-v2/pktline_test.go
git commit -m "spike: pkt-line framing helpers for relay v2 probe"
```

---

### Task 2: Advertisement probe + no-auth check

Confirm the two foundational assumptions: (a) the smart-HTTP v2 advertisement is what the spec's bridge expects — a `# service=git-upload-pack` banner + flush to strip, then `version 2` and the `ls-refs`/`fetch` capabilities; and (b) an unauthenticated request to a private repo is rejected at the advertisement GET (the exact point the relay's "fail-before-first-byte" invariant keys off).

**Files:**
- Create: `spike/relay-v2/main.go`

**Interfaces:**
- Consumes (from Task 1): `writePktLine`, `writeFlush`, `writeDelim`, `readPktLine`, `pktData`, `pktFlush`, `pktDelim`.
- Produces:
  - `func doGET(url, token, accept string) (*http.Response, error)`
  - `func doPOST(url, token, contentType string, body []byte) (*http.Response, error)`
  - `func readUntilFlush(r io.Reader) ([][]byte, error)`
  - `func pass(name string)` / `func fail(name, format string, a ...any)`
  - `func checkAdvertisement(base, token string)`
  - `func checkNoAuth(base string)`
  - `func main()`

- [ ] **Step 1: Write `main.go` with the advertisement + no-auth checks**

Create `spike/relay-v2/main.go`:

```go
// Command relay-v2 is a THROWAWAY spike that validates patvault's relay v2
// protocol assumptions against real GitHub. It is not part of the shipped
// binary; its pkt-line helpers inform internal/relay/pktline.go.
//
// Run:
//   SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2
// Use a private repo (or set SPIKE_PUBLIC=1 to skip the no-auth check).
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func pass(name string) { fmt.Printf("PASS: %s\n", name) }

func fail(name, format string, a ...any) {
	fmt.Printf("FAIL: %s: %s\n", name, fmt.Sprintf(format, a...))
	os.Exit(1)
}

func doGET(url, token, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.43.0")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return http.DefaultClient.Do(req)
}

func doPOST(url, token, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "git/2.43.0")
	return http.DefaultClient.Do(req)
}

// readUntilFlush reads data pkt-lines until the next flush-pkt, returning the
// data payloads (delim-pkts are skipped).
func readUntilFlush(r io.Reader) ([][]byte, error) {
	var out [][]byte
	for {
		p, kind, err := readPktLine(r)
		if err != nil {
			return out, err
		}
		switch kind {
		case pktFlush:
			return out, nil
		case pktData:
			out = append(out, p)
		}
	}
}

func checkAdvertisement(base, token string) {
	const name = "advertisement (upload-pack v2)"
	resp, err := doGET(base+"/info/refs?service=git-upload-pack", token,
		"application/x-git-upload-pack-advertisement")
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		fail(name, "content-type %q (want advertisement)", ct)
	}

	// First pkt-line is the service banner the SSH transport does NOT use.
	p, kind, err := readPktLine(resp.Body)
	if err != nil || kind != pktData || !strings.HasPrefix(string(p), "# service=git-upload-pack") {
		fail(name, "banner: p=%q kind=%d err=%v", p, kind, err)
	}
	// A flush terminates the banner.
	if _, kind, err = readPktLine(resp.Body); err != nil || kind != pktFlush {
		fail(name, "expected flush after banner: kind=%d err=%v", kind, err)
	}
	// The v2 advertisement follows, up to the next flush.
	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading advertisement: %v", err)
	}
	if len(lines) == 0 || strings.TrimSpace(string(lines[0])) != "version 2" {
		first := "<none>"
		if len(lines) > 0 {
			first = string(lines[0])
		}
		fail(name, "first advertisement line %q (want 'version 2')", first)
	}
	caps := map[string]bool{}
	for _, l := range lines[1:] {
		key := strings.SplitN(strings.TrimSpace(string(l)), "=", 2)[0]
		caps[key] = true
	}
	for _, need := range []string{"ls-refs", "fetch"} {
		if !caps[need] {
			fail(name, "missing capability %q", need)
		}
	}
	pass(name)
}

func checkNoAuth(base string) {
	const name = "no-auth rejected"
	resp, err := doGET(base+"/info/refs?service=git-upload-pack", "", "")
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	// The security-relevant invariant: an unauthenticated request must NOT
	// receive the advertisement. GitHub answers 401 or 404 for a private repo;
	// a 200 means the repo is public (re-run with SPIKE_PUBLIC=1) or, worse,
	// that unauth reached the advertisement.
	if resp.StatusCode == 200 {
		fail(name, "status 200 — unauthenticated request was NOT rejected "+
			"(is the repo public? set SPIKE_PUBLIC=1 to skip this check)")
	}
	pass(name)
	fmt.Printf("      unauthenticated status = %d\n", resp.StatusCode)
}

func main() {
	repo := os.Getenv("SPIKE_REPO")
	token := os.Getenv("SPIKE_TOKEN")
	if repo == "" || token == "" {
		fmt.Fprintln(os.Stderr, "set SPIKE_REPO=owner/repo and SPIKE_TOKEN=<fine-grained PAT>")
		os.Exit(2)
	}
	base := "https://github.com/" + repo + ".git"

	checkAdvertisement(base, token)
	if os.Getenv("SPIKE_PUBLIC") == "" {
		checkNoAuth(base)
	} else {
		fmt.Println("SKIP: no-auth rejected (SPIKE_PUBLIC set)")
	}

	fmt.Println("\n(advertisement checks passed)")
}
```

- [ ] **Step 2: Verify the package builds**

Run: `go build ./spike/relay-v2/`
Expected: no output, exit 0. (`go vet ./spike/relay-v2/` should also be clean.)

- [ ] **Step 3: Run against real GitHub**

Run (substitute your own private repo and a fine-grained PAT with Contents access to it):

```bash
SPIKE_REPO=your-owner/your-private-repo \
SPIKE_TOKEN=github_pat_xxx \
go run ./spike/relay-v2
```

Expected output:
```
PASS: advertisement (upload-pack v2)
PASS: no-auth rejected
      unauthenticated status = 401

(advertisement checks passed)
```

If `advertisement` fails on the banner or `version 2` line, the spec's banner-strip / v2 assumption is wrong — stop and record it (Task 5). If `no-auth` returns 200, the repo is public; re-run against a private repo or with `SPIKE_PUBLIC=1`.

- [ ] **Step 4: Commit**

```bash
git add spike/relay-v2/main.go
git commit -m "spike: advertisement probe + no-auth check for relay v2"
```

---

### Task 3: ls-refs round-trip

Confirm a hand-framed v2 `ls-refs` command POST returns the ref list, and extract HEAD's object id to drive the fetch in Task 4. This proves the first half of the "stateless-rpc pump": one self-contained command → one POST → one response.

**Files:**
- Modify: `spike/relay-v2/main.go` (add `lsRefs`; call it from `main`)

**Interfaces:**
- Consumes: `writePktLine`, `writeDelim`, `writeFlush`, `readUntilFlush`, `doPOST`, `pass`, `fail`.
- Produces: `func lsRefs(base, token string) string` — returns the HEAD object id (40-hex string).

- [ ] **Step 1: Add the `lsRefs` function**

Add to `spike/relay-v2/main.go`:

```go
// lsRefs sends a v2 ls-refs command and returns the object id of HEAD.
func lsRefs(base, token string) string {
	const name = "ls-refs round-trip"
	var body bytes.Buffer
	writePktLine(&body, "command=ls-refs\n")
	writePktLine(&body, "object-format=sha1\n")
	writeDelim(&body)
	writePktLine(&body, "peel\n")
	writePktLine(&body, "symrefs\n")
	writePktLine(&body, "ref-prefix HEAD\n")
	writeFlush(&body)

	resp, err := doPOST(base+"/git-upload-pack", token,
		"application/x-git-upload-pack-request", body.Bytes())
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading refs: %v", err)
	}
	var head string
	for _, l := range lines {
		fields := strings.Fields(string(l))
		if len(fields) >= 2 && fields[1] == "HEAD" {
			head = fields[0]
			break
		}
	}
	if head == "" {
		fail(name, "no HEAD ref found in %d ref lines", len(lines))
	}
	pass(name)
	fmt.Printf("      HEAD = %s\n", head)
	return head
}
```

- [ ] **Step 2: Call `lsRefs` from `main`**

In `spike/relay-v2/main.go`, replace this block in `main`:

```go
	fmt.Println("\n(advertisement checks passed)")
}
```

with:

```go
	head := lsRefs(base, token)
	_ = head

	fmt.Println("\n(advertisement + ls-refs checks passed)")
}
```

- [ ] **Step 3: Verify the package builds**

Run: `go build ./spike/relay-v2/`
Expected: no output, exit 0.

- [ ] **Step 4: Run against real GitHub**

Run:

```bash
SPIKE_REPO=your-owner/your-private-repo \
SPIKE_TOKEN=github_pat_xxx \
go run ./spike/relay-v2
```

Expected output (the HEAD id will differ):
```
PASS: advertisement (upload-pack v2)
PASS: no-auth rejected
      unauthenticated status = 401
PASS: ls-refs round-trip
      HEAD = 3f2a1c9e...

(advertisement + ls-refs checks passed)
```

- [ ] **Step 5: Commit**

```bash
git add spike/relay-v2/main.go
git commit -m "spike: ls-refs round-trip against real GitHub"
```

---

### Task 4: fetch round-trip (the core proof)

The decisive check: a hand-framed v2 `fetch` command (want HEAD, shallow `deepen 1`, `done`) POST returns a `packfile` section. Success here validates the whole v2 stateless-pump premise — two independent, self-contained commands over one logical session, each a single POST, with the PAT injected upstream.

**Files:**
- Modify: `spike/relay-v2/main.go` (add `fetchPack`; call it from `main`)

**Interfaces:**
- Consumes: `writePktLine`, `writeDelim`, `writeFlush`, `readPktLine`, `doPOST`, `pass`, `fail`, `pktFlush`, `pktDelim`.
- Produces: `func fetchPack(base, token, want string)`.

- [ ] **Step 1: Add the `fetchPack` function**

Add to `spike/relay-v2/main.go`:

```go
// fetchPack sends a v2 fetch command for a single want (shallow, done) and
// asserts the response contains a packfile section.
func fetchPack(base, token, want string) {
	const name = "fetch round-trip"
	var body bytes.Buffer
	writePktLine(&body, "command=fetch\n")
	writePktLine(&body, "object-format=sha1\n")
	writeDelim(&body)
	writePktLine(&body, "no-progress\n")
	writePktLine(&body, "deepen 1\n")
	writePktLine(&body, "want "+want+"\n")
	writePktLine(&body, "done\n")
	writeFlush(&body)

	resp, err := doPOST(base+"/git-upload-pack", token,
		"application/x-git-upload-pack-request", body.Bytes())
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}

	// Read pkt-lines until the "packfile" section header appears. Section
	// headers are plain data pkt-lines whose payload is the section name;
	// skip flush/delim and any other section (e.g. shallow-info). Once the
	// packfile header is seen the negotiation has succeeded and we stop
	// before the sideband-framed pack bytes.
	for {
		p, kind, err := readPktLine(resp.Body)
		if err != nil {
			fail(name, "reading response before packfile section: %v", err)
		}
		if kind == pktFlush || kind == pktDelim {
			continue
		}
		if strings.TrimSpace(string(p)) == "packfile" {
			pass(name)
			fmt.Println("      received packfile section header")
			return
		}
	}
}
```

- [ ] **Step 2: Call `fetchPack` from `main`**

In `spike/relay-v2/main.go`, replace this block in `main`:

```go
	head := lsRefs(base, token)
	_ = head

	fmt.Println("\n(advertisement + ls-refs checks passed)")
}
```

with:

```go
	head := lsRefs(base, token)
	fetchPack(base, token, head)

	fmt.Println("\nALL CHECKS PASSED — v2 protocol assumptions validated")
}
```

- [ ] **Step 3: Verify the package builds**

Run: `go build ./spike/relay-v2/`
Expected: no output, exit 0.

- [ ] **Step 4: Run against real GitHub**

Run:

```bash
SPIKE_REPO=your-owner/your-private-repo \
SPIKE_TOKEN=github_pat_xxx \
go run ./spike/relay-v2
```

Expected output:
```
PASS: advertisement (upload-pack v2)
PASS: no-auth rejected
      unauthenticated status = 401
PASS: ls-refs round-trip
      HEAD = 3f2a1c9e...
PASS: fetch round-trip
      received packfile section header

ALL CHECKS PASSED — v2 protocol assumptions validated
```

If `fetch` fails to reach a `packfile` header, capture the raw response (temporarily print each `p` in the loop) and record what section/error came back instead (Task 5) — this is exactly the kind of surprise the spike exists to surface.

- [ ] **Step 5: Commit**

```bash
git add spike/relay-v2/main.go
git commit -m "spike: fetch round-trip validates v2 stateless-pump premise"
```

---

### Task 5: Record findings, add README, decide disposition

The spike's deliverable is *knowledge*. Capture which spec assumptions held (or didn't), give the spike a README so it can be re-run, and decide whether to keep it as a reference or delete it.

**Files:**
- Create: `spike/relay-v2/README.md`
- Create: `docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md`

**Interfaces:**
- Consumes: the observed output from Tasks 2–4.
- Produces: documentation only.

- [ ] **Step 1: Write the spike README**

Create `spike/relay-v2/README.md`:

```markdown
# relay-v2 spike (throwaway)

Validates patvault's relay v2 protocol assumptions against **real GitHub**
before any relay/SSH code exists. Not part of the shipped binary.

## Run

    SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2

- Use a **private** repo so the no-auth (401) check is meaningful; otherwise
  set `SPIKE_PUBLIC=1` to skip it.
- The token must be a fine-grained PAT with Contents access to `SPIKE_REPO`.

## What it checks

1. `info/refs?service=git-upload-pack` advertisement: `# service=` banner +
   flush to strip, then `version 2` and `ls-refs`/`fetch` capabilities.
2. Unauthenticated advertisement GET is rejected (not 200; 401/404) — the point
   the relay's fail-before-first-byte invariant keys off.
3. `ls-refs` command POST returns refs; HEAD oid extracted.
4. `fetch` command POST (want HEAD, `deepen 1`, `done`) returns a `packfile`
   section.

`pktline.go` here is the reference the eventual `internal/relay/pktline.go`
mirrors.
```

- [ ] **Step 2: Write the findings note**

Create `docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md`, filling the RESULT/NOTES from what you actually observed running Tasks 2–4:

```markdown
# Relay v2 Spike — Findings (2026-07-16)

Spike: `spike/relay-v2/`. Validates the v2 smart-HTTP assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` against real GitHub.

| Assumption (from spec) | Result | Notes |
|---|---|---|
| `info/refs` prefixes a `# service=git-upload-pack` pkt-line + flush to strip | PASS/FAIL | <paste observed banner> |
| Advertisement is v2 (`version 2`) with `ls-refs` + `fetch` capabilities when `Git-Protocol: version=2` sent | PASS/FAIL | <observed caps> |
| Unauthenticated advertisement GET is rejected, not 200 (fail-before-first-byte trigger point) | PASS/FAIL/SKIP | <status seen: 401/404> |
| `ls-refs` command POST returns refs (single self-contained request) | PASS/FAIL | HEAD=<oid> |
| `fetch` command POST (want/deepen/done) returns a `packfile` section | PASS/FAIL | <sections seen> |
| PAT injection via `Authorization: Bearer` accepted on GET + POST | PASS/FAIL | |

## Surprises / deviations from the spec

<none, or describe — e.g. an unexpected section order, header requirement,
or content-type. Update the spec if an assumption was wrong.>

## Conclusion

<Assumptions hold → proceed to implement internal/relay per the spec. OR:
spec needs revision X before implementation.>

## Disposition of spike code

<Keep as reference for internal/relay/pktline.go, OR delete now that findings
are recorded.>
```

- [ ] **Step 3: Run the full spike once more and paste real output into the findings note**

Run: `SPIKE_REPO=... SPIKE_TOKEN=... go run ./spike/relay-v2`
Then fill the table's PASS/FAIL cells and the Notes/Surprises/Conclusion sections from the actual output. If any assumption FAILED, note the exact spec section to revise.

- [ ] **Step 4: Commit**

```bash
git add spike/relay-v2/README.md docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md
git commit -m "spike: record relay v2 protocol findings and disposition"
```

---

## Notes on scope

- This plan deliberately stops at *fetch*. Push (`git-receive-pack`) is the
  single-shot, lower-risk path per the spec and does not need a spike to
  de-risk; validating it would require mutating a real repo. If desired later,
  a `git-receive-pack` advertisement GET (read-only, no push) can be added as a
  sixth check to confirm the banner/auth shape on the write path.
- The spike hits real GitHub and cannot run in CI. Its unit-tested piece
  (`pktline_test.go`) is the only part that runs offline/deterministically.
- On completion, the next step is the full relay implementation plan
  (bottom-up: pktline → exec → authkeys → bridge → server → commands →
  end-to-end), written from the spec once these assumptions are confirmed.
