# Relay Slice 4 — Push Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `Bridge.Push` — the `git-receive-pack` advertisement GET, the `# service=` banner strip, and the single-shot commands+pack update POST — and wire it so that a **real `git push`** succeeds end-to-end against a `git-receive-pack`-backed stub upstream, with the pushed pack actually applied to the upstream repo.

**Architecture:** Push reuses everything slice 3 built. The advertisement phase is the *same* GET-strip-forward as fetch (the banner+flush framing is identical on `git-receive-pack`, confirmed by the push spike), so slice 4 parameterizes slice 3's `advertise` by service. The update phase is a single POST whose body is the client's stream copied to EOF — git sends commands + flush + a raw (un-pkt-line-framed) packfile then half-closes its write side, so the bridge never parses the pack. The body length is unknown up front, so the POST goes out **chunked** (`ContentLength = -1`); the `report-status` reply is pumped back to the client verbatim, sideband framing and `ng` rejection lines untouched.

**Tech Stack:** Go standard library (`bytes`, `context`, `errors`, `fmt`, `io`, `net/http`, `net/http/httptest`, `os`, `os/exec`, `path/filepath`, `strings`, `testing`), existing dependency `golang.org/x/crypto/ssh`, and the existing `internal/relay` package (`bridge.go`'s `Bridge`/`advertise`/`endpoint`/`setUpstreamHeaders`/`classifyStatus` from slice 3; `pktline.go`'s `readPacket`/`pktData`/`pktFlush` from slice 1; `server.go`'s `Request`/`bridge` interface from slice 2). No new dependencies.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-15-relay-design.md` is authoritative (§"Relay → GitHub" step "Push", §"Cross-cutting bridge rules", §"Sequence: `git push` through the relay"). `docs/superpowers/specs/2026-07-16-relay-implementation-design.md` §"Slice 4 — push bridge" defines this slice's scope. The two push probes are load-bearing inputs (see §"What is pinned"). Do not implement slice 5 (real GitHub) here.
- Go version: module targets `go 1.26.5` (from `go.mod`). Do not lower it.
- **No new dependencies.** `go.mod` / `go.sum` must be unchanged. Everything needed is already required.
- **Testing framework:** standard library `testing` only. Table-driven tests with `{name, ...}` struct slices and `t.Run(tc.name, ...)`, per `AGENTS.md` §Testing. In-package tests (`package relay`), matching how the repo tests unexported functions directly.
- **Visibility:** `Push` is already exported (slice 2's `bridge` interface). Every helper added here stays unexported (`pushPack`). Do not export new helpers. Do not touch `errors.go` — push reuses slice 3's `errGitHubAuth`/`errGitHubNotFound`/`errGitHubUnreachable` rows unchanged.
- **No wiring change.** `internal/commands/relay.go`'s `buildServeServer` already constructs the `Bridge`; once `Push` works, `patvault relay serve` does pushes with no edit. Do not touch `internal/commands/`.
- **Reuse, do not reimplement:** the advertisement phase is slice 3's `advertise`, parameterized by service. The banner strip is `readPacket` (slice 1). PAT injection, header set, and status mapping are slice 3's `setUpstreamHeaders` / `classifyStatus`, reused verbatim. Do not write a second advertisement path or a second status mapper.
- **The bridge never sees an `ssh.Channel`** — `Push` takes `io.Reader` / `io.Writer`. `bridge_test.go` drives it with `bytes.Buffer` / `httptest.Server`; no SSH.
- **Push body ends at the client's EOF.** `io.Copy` the client stream into the POST body until EOF; never parse the pack. A delete-only push (commands + flush, no pack) is the *same* code path — do not special-case it. (`2026-07-16-relay-push-framing-probe.md`.)
- **The push POST is chunked.** The body length is unknown up front, so set `httpReq.ContentLength = -1` to force `Transfer-Encoding: chunked` regardless of the body reader's concrete type — so a `*bytes.Reader` in a unit test frames the request the same way a real `ssh.Channel` does in production, and matches what git's own `remote-curl` sends. (Probed 2026-07-17: `ContentLength = -1` with a `*bytes.Reader` body yields `TransferEncoding=[chunked]` on the server side.)
- **Sideband pass-through is not optional.** The `report-status` reply may ride `side-band-64k` (channel 1) when the client requested it. Pump it byte-for-byte; **never reframe.** An unframed reply fails the push outright with `protocol error: bad band`. The relay gets correct framing for free by forwarding the client's capability request verbatim and pumping GitHub's reply untouched. (`2026-07-16-relay-push-framing-probe.md` §Findings.)
- **No loopback:** `Push` reads the client's commands+pack from `in` and writes the *report-status* to `out`. It must never feed `out` back into `in`. Pinned by `TestPushDoesNotLoopbackClientBytes`.
- **Fail-before-first-byte** is owned by the advertisement, exactly as fetch: nothing reaches `out` until the advertisement GET returns 2xx. Once the advertisement is forwarded, streaming has begun; a non-2xx **POST** is necessarily mid-stream and cannot be clean (`dispatch`'s `refuse` handles it). So assert zero-bytes only on advertisement failures, never on POST failures.
- **Never log the PAT** (base spec §"Operational logging"). The bridge does not log.
- Naming: `Test<FunctionName><Scenario>` — e.g. `TestPushStripsServiceBanner`.
- Exported identifiers get doc comments; unexported helpers that encode a probe-pinned contract carry one too.
- Gate for the whole slice: see §Slice gate. It is a **real `git push`** through the relay that actually advances the upstream ref, per the implementation design's anti-drift rule.

## What is pinned (these are the plan's inputs)

### From the push framing probe (`2026-07-16-relay-push-framing-probe.md`) — RUN, hermetic, reproducible

- **git half-closes after the pack.** The client sends commands + flush + a raw packfile, then EOFs its write side while still reading the response. `Push` copies `in` into the POST body until EOF and never looks at a pack byte.
- **A delete-only push sends no pack.** Commands + flush + EOF and commands + flush + pack + EOF are the *same* code path. Do not distinguish them.
- **The body goes out chunked** because its length is unknown until EOF. Go's `http.Client` chunks when `ContentLength < 0`.
- **Sideband framing is mandatory when the client asks for it.** An unframed `report-status` after the client requested `side-band-64k` earns `send-pack: protocol error: bad band #NNN` and aborts. Verbatim pass-through is the whole job.

### From the push spike (`2026-07-16-relay-push-spike-findings.md`) — RUN against real GitHub

- **receive-pack `info/refs` prefixes the same `# service=git-receive-pack` banner + flush** to strip. The relay's existing strip logic applies unchanged.
- **Upstream auth is HTTP Basic `x-access-token:<PAT>`** on the receive-pack endpoint too — same as upload-pack. `setUpstreamHeaders` is reused as-is.
- **Push is unaffected by the v2 gate.** receive-pack has no wire-protocol v2; sending `Git-Protocol: version=2` on the receive-pack requests is ignored (the spike sent it and got a classic advertisement). `dispatch` already skips the v2 gate for push (slice 2). Reusing `setUpstreamHeaders` (which sets `Git-Protocol: version=2`) is therefore safe on both push requests.
- **The `report-status` `ng` rejection path was never exercised against real GitHub** — every live command succeeded. It needs *stub* coverage here; the relay pumps it through regardless, so this is test coverage, not logic.
- **`report-status-v2` is a receive-pack capability, not wire protocol v2.** They are unrelated names. Nothing parses capabilities.

### From a probe run while writing this plan (2026-07-17) — read this, it grounds the e2e stub

`git receive-pack --stateless-rpc --advertise-refs <bare>` with `GIT_PROTOCOL` set emits the **classic** ref advertisement with **no** `# service=` banner. Observed first packet (git 2.53.0): `00b7caea8767…ab refs/heads/main\x00report-status report-status-v2 delete-refs side-band-64k quiet atomic object-format=sha1`. **Consequence:** the e2e stub's GET handler prepends the `# service=git-receive-pack\n` banner + flush itself (exactly as it already does for upload-pack), then pipes receive-pack's output. This is the same shape slice 3's upload-pack stub uses.

`git receive-pack --stateless-rpc <bare>` (no `--advertise-refs`) reads one stateless-rpc request from stdin, **applies the pack to `<bare>`**, and writes the `report-status` to stdout. **Consequence:** the e2e gate can assert the upstream ref actually moved after the push — ground truth, not a mock.

## File Structure

| Path | Responsibility |
|---|---|
| `internal/relay/bridge.go` | MODIFY. Parameterize `advertise` by service (`git-upload-pack` / `git-receive-pack`); update `Fetch`'s call. Implement `Push` (advertisement + `pushPack`) and `pushPack` (chunked commands+pack POST, verbatim report-status back). No new exported symbols. |
| `internal/relay/bridge_test.go` | MODIFY. Replace `TestPushReturnsErrorUntilSlice4` with the push suite: advertisement strip/headers/fail-before-first-byte/status-mapping, then body-streaming/chunked/verbatim-report-status/sideband+ng/delete-only/no-loopback. Add `stubReceivePackAdvertisement`, `stripBanner`, `pushCommands`, `sidebandReportStatus` helpers; extend `stubReq`/`newStubUpstream` for receive-pack POSTs. |
| `internal/relay/relay_e2e_test.go` | MODIFY. Generalize the slice-3 upload-pack stub backend to serve receive-pack too (`gitBackend`, `newStubUpstreamServer`), add `requireReceivePack` + `gitOutput`, and add the slice gate `TestRealGitPushThroughRelay`. |

Push does not add a file — it reuses slice 3's `bridge.go`. `errors.go` and `internal/commands/` are untouched.

---

### Task 1: `Push` advertisement — parameterize `advertise` by service, strip the receive-pack banner, fail-before-first-byte

This task makes the advertisement phase serve both fetch and push, then implements `Push`'s advertisement (GET `git-receive-pack`, strip the `# service=` banner+flush, forward the classic ref advertisement, map non-2xx to the upstream error rows before writing a byte). `pushPack` is a stub returning `nil` here; Task 2 fills it. All slice-3 fetch tests must stay green — they are the regression gate for the `advertise` refactor.

**Files:**
- Modify: `internal/relay/bridge.go`
- Test: `internal/relay/bridge_test.go`

**Interfaces:**
- Consumes: `readPacket` / `pktData` / `pktFlush` (slice 1); `endpoint`, `setUpstreamHeaders`, `classifyStatus`, `errGitHubUnreachable` (slice 3); `Request`, the `bridge` interface (slice 2).
- Produces:
  ```go
  func (b *Bridge) advertise(ctx context.Context, req Request, service string, out io.Writer) error // service: "git-upload-pack" | "git-receive-pack"
  func (b *Bridge) Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
  // unexported stub this task: pushPack (returns nil; real body is Task 2)
  ```

- [ ] **Step 1: Refactor `advertise` to take a service; update `Fetch`'s call**

In `internal/relay/bridge.go`, change `advertise`'s signature and its two hardcoded upload-pack strings to use the `service` parameter. Replace the whole `advertise` function with:

```go
// advertise does the GET for service ("git-upload-pack" or "git-receive-pack"),
// checks 2xx before writing anything, strips the smart-HTTP "# service=" banner +
// flush that the SSH transport does not use, and copies the remaining
// advertisement to out verbatim.
//
// Both directions share this: the banner+flush framing is identical on the
// upload-pack and receive-pack endpoints (confirmed by the push spike), and the
// strip logic does not interpret the payload — fetch's v2 capability
// advertisement and push's classic ref advertisement pump through the same code.
//
// readPacket reads exact lengths with io.ReadFull (no buffering), so consuming
// the banner and flush steals no bytes from the io.Copy that follows.
func (b *Bridge) advertise(ctx context.Context, req Request, service string, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		b.endpoint(req, "info/refs?service="+service), nil)
	if err != nil {
		return fmt.Errorf("build advertise request: %w", err)
	}
	setUpstreamHeaders(httpReq, req, "application/x-"+service+"-advertisement")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}

	// The smart-HTTP advertisement prefixes one data pkt-line (the
	// "# service=<service>" banner) and a flush-pkt that the SSH transport never
	// sends. Strip both, then pump the rest unchanged.
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
```

Then update `Fetch` to pass the service. Change its `advertise` call from `b.advertise(ctx, req, out)` to:

```go
	if err := b.advertise(ctx, req, "git-upload-pack", out); err != nil {
		return err
	}
```

- [ ] **Step 2: Replace `Push` and add the `pushPack` stub**

In `internal/relay/bridge.go`, replace the entire slice-3 `Push` stub (the one that returns `errors.New("push bridge not implemented (slice 4)")`) with:

```go
// Push is the receive-pack bridge: the advertisement GET (banner+flush stripped,
// then forwarded), then a single commands+pack POST whose report-status is
// streamed back verbatim.
//
// Fail-before-first-byte is owned by the advertisement, exactly as Fetch: nothing
// reaches out until the advertisement GET returns 2xx. Push is single-shot (one
// advertise, one update POST), where fetch is a command loop — receive-pack has
// no stateless-rpc command pump.
//
// The bridge is half-duplex in time (forward the advertisement, then read the
// client's commands+pack, then write the report-status), which is what makes the
// aliased ssh.Channel-as-both-in-and-out safe. See
// docs/superpowers/notes/2026-07-17-relay-slice-3-channel-aliasing.md.
func (b *Bridge) Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	if err := b.advertise(ctx, req, "git-receive-pack", out); err != nil {
		return err
	}
	return b.pushPack(ctx, req, in, out)
}

// pushPack is Task 2. Task 1 ships the advertisement only.
func (b *Bridge) pushPack(_ context.Context, _ Request, in io.Reader, _ io.Writer) error {
	_ = in
	return nil
}
```

Remove the now-unused `"errors"` import **only if** nothing else in `bridge.go` uses it — `pumpCommands` still calls `errors.Is(err, io.EOF)`, so `"errors"` stays. Leave the import block unchanged.

- [ ] **Step 3: Replace `TestPushReturnsErrorUntilSlice4` and add the push-advertisement helpers + tests**

In `internal/relay/bridge_test.go`:

First, DRY the banner-strip helper. Replace the existing `advWithoutBanner` function with:

```go
// advWithoutBanner is stubAdvertisement with the banner+flush removed — what the
// fetch bridge must write to out.
func advWithoutBanner() []byte {
	return stripBanner(stubAdvertisement())
}

// stripBanner drops the first two packets (the "# service=" banner data pkt and
// its flush) from a smart-HTTP advertisement, returning what the bridge forwards.
// Shared by the fetch and push advertisement assertions.
func stripBanner(full []byte) []byte {
	r := bytes.NewReader(full)
	readPacket(r) // banner
	readPacket(r) // flush
	rest, _ := io.ReadAll(r)
	return rest
}

// stubReceivePackAdvertisement is a real-shape classic (non-v2) ref advertisement
// — the ref line + NUL-separated capabilities git-receive-pack emits — prefixed
// with the smart-HTTP "# service=git-receive-pack" banner + flush the SSH
// transport does not use and the bridge must strip.
func stubReceivePackAdvertisement() []byte {
	var b strings.Builder
	writePkt(&b, "# service=git-receive-pack\n")
	writeFlush(&b)
	writePkt(&b, "caea8767d0ef709639db64552a8d5d87957301ab refs/heads/main\x00"+
		"report-status report-status-v2 delete-refs side-band-64k quiet atomic object-format=sha1\n")
	writeFlush(&b)
	return []byte(b.String())
}
```

Then delete `TestPushReturnsErrorUntilSlice4` entirely and add:

```go
func TestPushStripsServiceBannerAndForwardsAdvertisement(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("Push returned %v", err)
	}
	want := stripBanner(stubReceivePackAdvertisement())
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant advertisement without banner:\n%q", got, want)
	}
	if bytes.Contains(out.Bytes(), []byte("# service=")) {
		t.Errorf("out still contains the # service= banner:\n%q", out.Bytes())
	}
	if len(stub.recordedGets()) != 1 {
		t.Errorf("recorded %d GETs, want 1", len(stub.recordedGets()))
	}
}

func TestPushAdvertisementInjectsHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	gets := stub.recordedGets()
	if len(gets) != 1 {
		t.Fatalf("recorded %d GETs, want 1", len(gets))
	}
	g := gets[0]
	if got := basicAuth(g.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("GET Authorization = %q, want Basic x-access-token:ghp_secret", g.auth)
	}
	if g.accept != "application/x-git-receive-pack-advertisement" {
		t.Errorf("GET Accept = %q, want receive-pack advertisement", g.accept)
	}
}

func TestPushFailBeforeFirstByteOn500(t *testing.T) {
	stub := newStubUpstream(t, nil, nil, http.StatusInternalServerError, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0 (fail-before-first-byte): %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(500)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("Push returned %v, want a *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("Push error = %v (retryable %v), want %v (retryable true)", re, re.Retryable(), want)
	}
}

func TestPushAdvertisementMapsStatusToErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   *relayError
	}{
		{"401 maps to auth", http.StatusUnauthorized, errGitHubAuth("owner/repo")},
		{"403 maps to auth", http.StatusForbidden, errGitHubAuth("owner/repo")},
		{"404 maps to not-found", http.StatusNotFound, errGitHubNotFound("owner/repo")},
		{"503 maps to unreachable", http.StatusServiceUnavailable, errGitHubUnreachable(503)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubUpstream(t, nil, nil, tc.status, 0)
			b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}
			err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), io.Discard)
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
```

- [ ] **Step 4: Run the tests to verify they pass (and fetch stays green)**

Run: `go test ./internal/relay/...`
Expected: PASS — the new push-advertisement tests, and **all** slice-3 fetch tests (the `advertise` refactor's regression gate). If a fetch test fails, the refactor changed fetch's behavior — revert to the exact strings/URL fetch used (`info/refs?service=git-upload-pack`, `application/x-git-upload-pack-advertisement`).

- [ ] **Step 5: Commit**

```bash
git add internal/relay/bridge.go internal/relay/bridge_test.go
git commit -m "feat(relay): push advertisement, sharing the fetch banner strip

Parameterize advertise by service so git-receive-pack reuses the # service=
banner+flush strip verbatim (identical framing, confirmed by the push spike).
Push does the receive-pack advertisement GET, maps non-2xx to the upstream error
rows before writing a byte, and forwards the classic ref advertisement. pushPack
is stubbed until the next commit.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

---

### Task 2: `pushPack` — chunked commands+pack POST, verbatim report-status back

This task replaces the `pushPack` stub with the real update phase: POST the client's stream (`in`) to `git-receive-pack` as a chunked body, stream the `report-status` reply to `out` untouched. It pins the chunked framing, the verbatim/no-loopback/sideband+ng/delete-only properties, and the receive-pack POST headers.

**Files:**
- Modify: `internal/relay/bridge.go` (replace `pushPack`)
- Test: `internal/relay/bridge_test.go` (extend the stub for receive-pack POSTs; add the update-phase tests)

**Interfaces:**
- Consumes: `endpoint`, `setUpstreamHeaders`, `classifyStatus`, `errGitHubUnreachable` (slice 3).
- Produces: the completed `Push`; no new exported symbols.

- [ ] **Step 1: Write the failing tests**

In `internal/relay/bridge_test.go`, first extend the stub to record and serve receive-pack POSTs. Add a `chunked` field to `stubReq`:

```go
// stubReq records one upstream request's headers and body.
type stubReq struct {
	auth, gitProto, accept, ctype string
	chunked                       bool
	body                          []byte
}
```

In `newStubUpstream`'s handler, record `chunked` in the `rec` literal (the request is chunked when it has a Transfer-Encoding):

```go
		rec := stubReq{
			auth: r.Header.Get("Authorization"), gitProto: r.Header.Get("Git-Protocol"),
			accept: r.Header.Get("Accept"), ctype: r.Header.Get("Content-Type"),
			chunked: len(r.TransferEncoding) > 0, body: body,
		}
```

And add a receive-pack POST branch alongside the existing `git-upload-pack` one (same recording + response behavior):

```go
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-receive-pack"):
			s.mu.Lock()
			s.posts = append(s.posts, rec)
			s.mu.Unlock()
			if s.postStatus != 0 {
				w.WriteHeader(s.postStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			io.Copy(w, s.postResp())
```

Then add the update-phase helpers and tests:

```go
// pushCommands is a hand-rolled receive-pack request body: one ref-update command
// pkt-line (old-oid new-oid ref, NUL, capabilities), a flush-pkt, then a stand-in
// "pack" (the bridge never parses it, so opaque bytes are faithful — git sends a
// raw, un-pkt-line-framed pack here). withPack=false is the delete-only shape:
// commands + flush and nothing after.
func pushCommands(withPack bool) []byte {
	var b strings.Builder
	writePkt(&b, "0000000000000000000000000000000000000000 "+
		"bf13b4419cf93eabd9b18d4ad9c2210a9268fdef refs/heads/main\x00"+
		"report-status side-band-64k object-format=sha1 agent=git/2.53.0-Linux")
	writeFlush(&b)
	out := []byte(b.String())
	if withPack {
		out = append(out, []byte("PACK\x00\x00\x00\x02rawpackbytes-not-pkt-framed")...)
	}
	return out
}

// sidebandReportStatus is a report-status riding sideband channel 1 (\x01), the
// framing GitHub uses when the client requested side-band-64k. It carries an `ng`
// rejection line — the path the live push spike never exercised. The bridge must
// reproduce these bytes exactly; reframing them breaks the client with "bad band".
func sidebandReportStatus() []byte {
	var status strings.Builder
	writePkt(&status, "unpack ok\n")
	writePkt(&status, "ng refs/heads/main non-fast-forward\n")
	writeFlush(&status)
	var b strings.Builder
	writePkt(&b, "\x01"+status.String()) // one band-1 chunk carrying the status
	writeFlush(&b)
	return []byte(b.String())
}

func TestPushStreamsClientBodyToUpstreamAndReportStatusBack(t *testing.T) {
	report := []byte("000eunpack ok\n0019ok refs/heads/main\n0000")
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(true)
	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}

	// out = advertisement (banner stripped) + report-status, verbatim.
	want := append(stripBanner(stubReceivePackAdvertisement()), report...)
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant\n%q", got, want)
	}
	// The upstream received the client's commands+pack byte-for-byte.
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !bytes.Equal(posts[0].body, body) {
		t.Errorf("POST body = %q, want the client's commands+pack %q", posts[0].body, body)
	}
}

func TestPushSendsChunkedRequestBody(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(pushCommands(true)), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !posts[0].chunked {
		t.Error("receive-pack POST was not chunked; the body length is unknown up front and must go out chunked")
	}
}

func TestPushInjectsPostHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, bytes.NewReader(pushCommands(true)), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	p := stub.recordedPosts()[0]
	if got := basicAuth(p.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("POST Authorization = %q, want Basic x-access-token:ghp_secret", p.auth)
	}
	if p.ctype != "application/x-git-receive-pack-request" {
		t.Errorf("POST Content-Type = %q, want receive-pack-request", p.ctype)
	}
	if p.accept != "application/x-git-receive-pack-result" {
		t.Errorf("POST Accept = %q, want receive-pack-result", p.accept)
	}
}

// The report-status may be sideband-framed and may carry `ng` rejection lines.
// The bridge pumps it byte-for-byte; a single reframed byte breaks the client.
func TestPushForwardsSidebandReportStatusVerbatim(t *testing.T) {
	report := sidebandReportStatus()
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(pushCommands(true)), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	tail := out.Bytes()[len(stripBanner(stubReceivePackAdvertisement())):]
	if !bytes.Equal(tail, report) {
		t.Errorf("report-status not forwarded verbatim:\ngot  %q\nwant %q", tail, report)
	}
	if !bytes.Contains(tail, []byte{0x01}) {
		t.Error("sideband channel marker (\\x01) was stripped — the bridge reframed the reply")
	}
	if !bytes.Contains(tail, []byte("ng refs/heads/main")) {
		t.Error("ng rejection line did not survive pass-through")
	}
}

// A delete-only push sends commands + flush and no pack. It is the same code
// path: the body ends at the client's EOF regardless of whether a pack followed.
func TestPushDeleteOnlyHasNoPack(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(false) // commands + flush, no pack
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !bytes.Equal(posts[0].body, body) {
		t.Errorf("delete-only POST body = %q, want commands+flush %q", posts[0].body, body)
	}
}

// The channel-aliasing pin for push: the bridge must never echo the client's
// commands+pack back to out. Only the advertisement and the report-status appear.
func TestPushDoesNotLoopbackClientBytes(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(true)
	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("rawpackbytes-not-pkt-framed")) {
		t.Errorf("client pack bytes were echoed back to out (loopback):\nout=%q", out.Bytes())
	}
	if bytes.Contains(out.Bytes(), []byte("refs/heads/main\x00report-status side-band-64k")) {
		t.Errorf("client command bytes leaked into out:\n%q", out.Bytes())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/relay/...`
Expected: FAIL — `pushPack` is a stub that reads nothing and returns `nil`, so the stub records zero POSTs and `out` carries only the advertisement.

- [ ] **Step 3: Write the implementation**

In `internal/relay/bridge.go`, replace the `pushPack` stub with:

```go
// pushPack streams the client's ref-update commands + packfile to
// git-receive-pack and streams the report-status back verbatim.
//
// The body is the client's stream copied until EOF: git sends commands + flush +
// a raw (un-pkt-line-framed) packfile and then half-closes its write side, so the
// bridge never parses the pack. A delete-only push (commands + flush, no pack) is
// the same code path. The body length is unknown until EOF, so the POST goes out
// chunked (ContentLength = -1) — the same framing in production (an ssh.Channel
// body) and in tests (a *bytes.Reader body), and what git's own remote-curl
// sends. See docs/superpowers/notes/2026-07-16-relay-push-framing-probe.md.
//
// The report-status reply — possibly sideband-framed (side-band-64k) and possibly
// carrying `ng` rejection lines — is pumped to out untouched. Reframing it breaks
// the client outright ("bad band"); pass-through is the whole job.
func (b *Bridge) pushPack(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.endpoint(req, "git-receive-pack"), in)
	if err != nil {
		return fmt.Errorf("build receive-pack request: %w", err)
	}
	// Force chunked: the length is unknown until the client's EOF.
	httpReq.ContentLength = -1
	setUpstreamHeaders(httpReq, req, "application/x-git-receive-pack-request")
	httpReq.Header.Set("Accept", "application/x-git-receive-pack-result")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy report-status: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/relay/...`
Expected: PASS — the streaming, chunked, POST-headers, sideband+ng, delete-only, and no-loopback tests, plus every slice-1..3 test.

- [ ] **Step 5: Commit**

```bash
git add internal/relay/bridge.go internal/relay/bridge_test.go
git commit -m "feat(relay): push update phase -- chunked commands+pack, verbatim report-status

pushPack POSTs the client's stream to git-receive-pack as a chunked body (length
unknown until the client's EOF; ContentLength = -1 so tests and production frame
it identically), and streams the report-status back untouched -- sideband framing
and ng rejection lines pass through. A delete-only push (no pack) is the same
code path. Pins no-loopback and the chunked framing.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
"
```

---

### Task 3: The slice gate — real `git push` through the relay that advances the upstream ref

The anti-drift gate. A real `git push`, a real relay with a real `Bridge`, and a real (git-backed) stub upstream exchange real receive-pack bytes — including a raw packfile the relay pumps to EOF and a sideband-framed report-status it pumps back untouched. The upstream ref must actually move: the pushed pack is applied by `git receive-pack`, so this catches a byte-wrong bridge against ground truth.

**Files:**
- Modify: `internal/relay/relay_e2e_test.go`

**Interfaces:**
- Consumes: `Bridge`, `Server` (slice 3 + slice 2); `requireGit`, `newE2EKey`, `writeClientKey`, `startRelay`, `newTestServer`, `storePAT`, `makeSourceRepo`, `mustRunGit`, `runGitOK` (slice 2 + slice 3); `writePkt` / `writeFlush` (`bridge_test.go`).
- Produces: `TestRealGitPushThroughRelay`; the generalized `gitBackend` / `newStubUpstreamServer`; `requireReceivePack`, `gitOutput`.

- [ ] **Step 1: Generalize the stub upstream backend to serve receive-pack**

In `internal/relay/relay_e2e_test.go`, **replace** the slice-3 `uploadPackRepo` and `newStubUpstreamServer` functions with a service-parameterized backend and a two-service router:

```go
// gitBackend runs git-<service> --stateless-rpc against repo, the way
// git http-backend does internally. service is "upload-pack" or "receive-pack".
// When advertise is true it runs --advertise-refs (no stdin) and the caller
// prepends the smart-HTTP "# service=" banner+flush. Otherwise it reads one
// stateless-rpc request from stdin and returns the response — refs+pack for
// upload-pack; report-status for receive-pack, which also APPLIES the pushed pack
// to repo. GIT_PROTOCOL comes from the request so the stub mirrors the real
// server's protocol negotiation. Real git produces the bytes, so the framing the
// relay pumps is ground truth, not invented.
func gitBackend(t *testing.T, service, repo string, advertise bool, gitProto string, stdin io.Reader) []byte {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-"+service)
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
		t.Fatalf("git-%s %v: %v\n%s", service, args, err, stderr.String())
	}
	return data
}

// newStubUpstreamServer stands up an httptest.Server that serves repo over the
// smart-HTTP protocol by delegating to git-upload-pack (fetch) and
// git-receive-pack (push). Real git produces the bytes — advertisement, refs,
// packfile, report-status — so the framing the relay pumps is ground truth. The
// URL path is matched by suffix; the service comes from the ?service= query.
func newStubUpstreamServer(t *testing.T, repo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gitProto := r.Header.Get("Git-Protocol")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "info/refs"):
			service := strings.TrimPrefix(r.URL.Query().Get("service"), "git-")
			adv := gitBackend(t, service, repo, true, gitProto, nil)
			// Prepend the smart-HTTP banner+flush that --advertise-refs omits (git
			// http-backend adds it; the stub replicates that). Probed 2026-07-17:
			// receive-pack --advertise-refs emits the classic advertisement with
			// no banner, exactly as upload-pack does.
			writePkt(w, "# service=git-"+service+"\n")
			writeFlush(w)
			w.Write(adv)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-upload-pack"):
			w.Write(gitBackend(t, "upload-pack", repo, false, gitProto, r.Body))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-receive-pack"):
			w.Write(gitBackend(t, "receive-pack", repo, false, gitProto, r.Body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
```

Note: the slice-3 fetch gate (`TestRealGitCloneAndIncrementalFetchThroughRelay`) calls `newStubUpstreamServer` — it keeps working because the upload-pack routes are unchanged in behavior (`gitBackend(t, "upload-pack", …)` is `uploadPackRepo` renamed). The slice-3 `requireUploadPack` helper stays as-is.

- [ ] **Step 2: Add `requireReceivePack` and `gitOutput`**

Append to `internal/relay/relay_e2e_test.go`:

```go
// requireReceivePack skips when git-receive-pack is not installed. The e2e stub
// upstream shells out to it (as git http-backend does internally) so a real
// report-status — and a real pack application — is produced by git itself.
func requireReceivePack(t *testing.T) {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path failed: %v", err)
		return
	}
	bin := filepath.Join(strings.TrimSpace(string(out)), "git-receive-pack")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("git-receive-pack not found at %s", bin)
	}
}

// gitOutput runs git in dir, fails the test on error, and returns stdout+stderr.
// The mirror of mustRunGit (which discards output) for assertions that read a
// value back — e.g. rev-parse. No SSH env; for local repo inspection only.
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}
```

- [ ] **Step 3: Add the gate test**

Append to `internal/relay/relay_e2e_test.go`:

```go
// The slice-4 gate. A real git push through the relay backed by a
// git-receive-pack stub upstream must succeed end to end AND advance the upstream
// ref. This is the anti-drift gate: the real client, the real relay, and a real
// (git-backed) upstream exchange real receive-pack bytes — a raw packfile the
// relay pumps to EOF and a sideband-framed report-status it pumps back untouched.
// The upstream ref moving proves the pushed pack was applied, not just echoed.
func TestRealGitPushThroughRelay(t *testing.T) {
	requireGit(t)
	requireReceivePack(t)

	priv, signer := newE2EKey(t)
	dir := t.TempDir()
	keyPath := writeClientKey(t, dir, priv)

	// Upstream: a bare repo seeded from a real work repo with content.
	src := makeSourceRepo(t)
	bare := filepath.Join(t.TempDir(), "e2erepo.git")
	mustRunGit(t, src, "clone", "--bare", "-q", src, bare)
	baseSHA := strings.Fields(gitOutput(t, bare, "rev-parse", "main"))[0]
	upstream := newStubUpstreamServer(t, bare)

	// Relay: real Server, real Bridge pointed at the stub upstream.
	s := newTestServer(t, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	s.Bridge = &Bridge{Client: upstream.Client(), BaseURL: upstream.URL}
	storePAT(t, s.OpenDB, s.Keyring, "owner/e2erepo", "ghp_stub", nil)
	addr := startRelay(t, s)

	// A local work clone (straight from the bare on disk) to push FROM.
	work := filepath.Join(t.TempDir(), "work")
	mustRunGit(t, filepath.Dir(work), "clone", "-q", bare, work)
	mustRunGit(t, work, "config", "user.email", "relay-e2e@example.invalid")
	mustRunGit(t, work, "config", "user.name", "relay-e2e")
	if err := os.WriteFile(filepath.Join(work, "pushed.txt"),
		[]byte("pushed through the relay\n"), 0o644); err != nil {
		t.Fatalf("write pushed.txt: %v", err)
	}
	mustRunGit(t, work, "add", "pushed.txt")
	mustRunGit(t, work, "commit", "-q", "-m", "second")
	newSHA := strings.Fields(gitOutput(t, work, "rev-parse", "HEAD"))[0]

	// Push through the relay.
	pushURL := "ssh://git@" + addr + "/owner/e2erepo.git"
	out := runGitOK(t, work, keyPath, nil, "push", pushURL, "HEAD:refs/heads/main")
	// The PAT the relay injected upstream must never reach the client.
	if strings.Contains(out, "ghp_stub") {
		t.Errorf("push output leaked the PAT: %q", out)
	}

	// The upstream ref must now be at the pushed commit — the pack was applied.
	after := strings.Fields(gitOutput(t, bare, "rev-parse", "main"))[0]
	if after == baseSHA {
		t.Errorf("upstream main did not move: still %s", baseSHA)
	}
	if after != newSHA {
		t.Errorf("upstream main = %s, want the pushed commit %s", after, newSHA)
	}
}
```

- [ ] **Step 4: Run the gate**

Run: `go test -run TestRealGitPushThroughRelay -v ./internal/relay/...`
Expected: PASS. If it skips with `git-receive-pack not found`, the environment lacks the binary; the test is correct. If the push fails with a `patvault:` message, read it — the gate is doing its job (that line names the failing check). If the push hangs, `pushPack` is not draining `in` to EOF or not streaming the report-status before returning — re-check that the POST body is `in` (not a buffered copy) and that `ContentLength = -1`.

- [ ] **Step 5: Run the full suite with the race detector**

Run: `go test -race ./...`
Expected: PASS. The race detector matters here: `pushPack` streams `in` into the POST body concurrently with the SSH channel's read/write halves, and a data race would indicate the aliasing contract is violated.

- [ ] **Step 6: Commit**

```bash
git add internal/relay/relay_e2e_test.go
git commit -m "test(relay): real git push through the relay advances the upstream ref

Slice-4 anti-drift gate. Drives real git push at a real relay backed by a
git-receive-pack stub upstream (real pack, real sideband report-status). Asserts
the upstream ref actually moved to the pushed commit -- the pack was applied, not
echoed -- and that the injected PAT never reaches the client. Generalizes the
slice-3 upload-pack stub backend to serve both services.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
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

all pass, and specifically **`TestRealGitPushThroughRelay` passes (not skips** — `git` and `git-receive-pack` must be on PATH), advancing the upstream ref. Together with slice 3's `TestRealGitCloneAndIncrementalFetchThroughRelay`, the relay now does a real clone, a real incremental fetch, and a real push against a git-backed upstream — the implementation design's anti-drift gates for the fetch and push directions.

## Out of scope (do not do in this slice)

- **Real GitHub.** Slice 5 confirms that GitHub's receive-pack endpoint accepts a **chunked** request body (this slice proves the relay *emits* chunked; a standards-compliant HTTP/1.1 server — the Go httptest stub — accepts it, but real GitHub is unverified), and confirms the status→message mapping against the real Git endpoints. Do not add credentials or network calls.
- **Buffering the pack to compute a Content-Length.** Only needed if GitHub rejects chunked (slice 5's finding). Do not pre-empt it — it is in tension with "stream, never buffer".
- **Interpreting the pack, the commands, or the report-status.** The push path is a pump. Do not parse `ng` lines, count objects, or inspect capabilities beyond the two advertisement packets `advertise` strips. The `ng` test asserts *pass-through*, not handling.
- **Push-time policy** (force-push denial, deletion denial, approval-on-push). Deferred to v2 by the base spec's §Non-goals. The relay is transparent in v1.
- **`errors.go` changes.** Push reuses slice 3's `errGitHub*` rows unchanged. Add no new error constructors.
