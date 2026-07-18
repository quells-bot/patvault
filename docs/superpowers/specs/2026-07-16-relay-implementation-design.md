# Relay Implementation: Slicing and Seams

**Status:** addendum to `2026-07-15-relay-design.md`, which remains
**authoritative** for every design decision — architecture, wire protocol, error
table, module layout, threat model. This document does not revisit them. It
answers a narrower question: *in what order do we build `internal/relay`, and
what stops the pieces from drifting apart in between?*

## The constraint

Break the work into manageable, testable chunks that are unlikely to introduce
drift between them.

"Drift" is the specific failure this design is shaped against: building two
halves of the relay against an *imagined* interface and discovering at
integration time that they do not fit. It is why the obvious decomposition —
"build `bridge.go` first, then `server.go`, then wire them together" — is
rejected here. Each half would be unit-green and the seam untested until the
end.

## The anti-drift rule

**Every slice after the first ends with real `git` driving the real relay.** Not
a unit test, not a mock — the actual `git` binary, as a subprocess, doing a real
`clone` / `fetch` / `push`. A seam exercised by a real client at every step
cannot silently drift.

This is affordable because the spikes already proved a real `git` can be driven
at an in-process server hermetically, with no credentials and no network
(`spike/relay-ssh/`, `spike/relay-push-frame/`).

A second rule supports it: **the stub upstream is built from bytes the spikes
actually recorded** — the real `# service=` banner and flush, the real capability
list, the real `unpack ok` / `ok <ref>` — not from a reading of the spec. Testing
against a stub we imagined would reproduce the exact failure mode
(`docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md` §Corrections)
that this project has already paid for once.

## Slices

| # | Scope | Gate |
|---|---|---|
| 1 | `pktline.go`, `exec.go` | `go test` — pure functions, spike-pinned inputs |
| 2 | `authkeys.go`, `server.go`, `commands/relay.go`, `errors.go` | **real `git clone`** gets the right `patvault:` stderr + exit code; no upstream exists yet |
| 3 | `bridge.go` fetch path + stub upstream | **real `git clone`** and incremental **`git fetch`** succeed end-to-end |
| 4 | `bridge.go` push path | **real `git push`** succeeds; delete-ref push succeeds |
| 5 | Real-GitHub verification | manual run closes the last two unverified assumptions |

### Slice 1 — the pure leaves

`pktline.go` (length-prefix scanner; flush/delim boundaries) and `exec.go`
(`parseExec`). No I/O, no dependencies on the rest of the relay, and the spikes
pinned their exact inputs. Nothing to drift against.

### Slice 2 — the SSH front door that refuses everything

Host key persistence, publickey auth against the allowlist, `GIT_PROTOCOL`
capture, exec dispatch, the v2 gate, repo resolution, expiry check, and the
stderr + `exit-status` error surface. **No upstream at all.**

The point of this slice: a large share of the spec's error table, and the whole
fail-before-first-byte invariant, are testable *without any upstream*. A v0
fetch, an unlisted key, a `git-upload-archive`, a repo with no stored PAT, and an
expired PAT are all refused before the relay would ever contact GitHub. That is
real end-to-end coverage of the front door, gated on real `git`, before
`bridge.go` exists.

### Slice 3 — stub upstream + fetch bridge

The money slice: `bridge.go`'s advertisement GET, banner+flush strip, and v2
stateless-rpc command pump. Ends with a real `git clone` working through the
relay.

### Slice 4 — push bridge

Small, because slice 3 built everything it reuses. The push path is
`io.Copy(postBody, in)` until EOF plus sideband pass-through
(`docs/superpowers/notes/2026-07-16-relay-push-framing-probe.md`).
`spike/relay-push-frame/`'s `handlePush` is already the shape of the stub this
tests against.

### Slice 5 — real GitHub

The only slice needing credentials: a fresh private repo and a fine-grained PAT.
Closes the two open assumptions below. Kept separate precisely because the stub
can drift from real GitHub, and that risk deserves its own gate rather than being
folded into a slice that would otherwise be hermetic.

## The seam

Named here, before slice 2 ships, so slice 2 cannot grow a shape slice 3 cannot
use.

```go
// Request carries everything the bridge needs. By the time it is built, every
// fallible check (auth, exec parse, v2 gate, repo resolution, expiry, decrypt)
// has already passed.
type Request struct {
    Repo string // normalized "owner/repo", already shape-checked
    PAT  string // decrypted, already expiry-checked
}

type Bridge struct {
    Client  *http.Client // fakable, per the base spec's DI note
    BaseURL string       // "https://github.com"; the stub swaps this
}

// Fetch runs the v2 stateless-rpc pump. Push copies to EOF.
// Neither may write a single byte to out until the upstream advertisement
// has returned 2xx.
func (b *Bridge) Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error
func (b *Bridge) Push(ctx context.Context, req Request, in io.Reader, out io.Writer) error
```

Three consequences, each load-bearing:

- **The bridge never sees an `ssh.Channel`.** It takes `io.Reader` / `io.Writer`,
  so `bridge_test.go` drives it with `bytes.Buffer` and no SSH.
- **`BaseURL` is what makes slice 3's gate possible.** Without an injectable
  upstream there is no way to point a real relay at a stub, and the end-to-end
  test cannot exist.
- **Fail-before-first-byte reduces to one rule the bridge owns:** do not write to
  `out` until the advertisement is 2xx. Directly testable — stub returns 500,
  assert zero bytes reached a spy writer.

### Deviation from the base spec's module layout

`internal/relay/errors.go` is **added**. The base spec's layout table lists five
files, none of which owns the condition → (message, exit code, retryable) table
from §"Errors and exit codes". One file, one table, one test against the spec's
wording. This is the only departure from that table.

## What the spikes constrain

These are the plan's inputs. Five of the six are things a reasonable implementer
would otherwise get wrong:

1. **The v2 gate compares the value.** `GIT_PROTOCOL == "version=2"`. Presence
   alone fails open: `protocol.version=1` *does* send the env request, carrying
   `version=1`. (relay-ssh)
2. **`parseExec` shell-word splits.** Git emits POSIX quoting; the path
   `/owner/it's.git` arrives as `'/owner/it'\''s.git'`. Stripping the first and
   last quote is wrong. (relay-ssh)
3. **The path is the URL's path, verbatim.** Git neither appends nor strips
   `.git`; the suffix is the user's remote URL's business. Handle both. (relay-ssh)
4. **Upstream auth is HTTP Basic** `x-access-token:<PAT>`, not Bearer — on both
   the upload-pack and receive-pack endpoints. (relay-v2, relay-push)
5. **The push body ends at the client's EOF.** No pack parsing; a delete-only
   push (no pack) is the same code path. (relay-push-frame)
6. **Sideband framing is load-bearing.** An unframed `report-status` when the
   client asked for `side-band-64k` fails the push outright with `protocol error:
   bad band`. The relay gets this free by pumping GitHub's reply untouched — but
   only if it does not "helpfully" reframe. (relay-push-frame)

And two things nothing may depend on, because they were never observed:

- **Fetch section order** (whether `shallow-info` precedes `packfile`). The
  bridge does not interpret sections, so this is fine — but nothing may start.
- **The `report-status` `ng` rejection path.** Every command in the live push run
  succeeded. Needs stub coverage in slice 4; the relay pumps it through
  regardless, so this is test coverage, not logic.

## Open items

**All SETTLED (2026-07-18)** — see
`docs/superpowers/notes/2026-07-18-relay-slice-5-real-github-findings.md`. The
base spec's §"Unverified assumptions" had three live bullets; all are now closed:

- **The pack body streamed end to end** — closed by slices 3–4's gates and the
  slice-5 real-GitHub run (real clone/fetch/push stream real packs, sideband
  report-status forwarded verbatim).
- **GitHub accepting a chunked receive-pack request body** — **accepted.** A real
  push through the relay went out chunked and succeeded; no buffering fallback was
  needed. (Slice 5 did surface an unrelated delete-only-push bug — git does not
  half-close for a no-pack push, so the relay now sends an all-delete command list
  with a known `Content-Length`; fixed and re-verified.)
- **The status→message mapping** — observed 200 / 401 / 404; `classifyStatus`
  matches the table as-is. The revoked-vs-expired distinction stays non-actionable
  (both map to the same auth message; an expired PAT is refused locally).

## Non-goals

Unchanged from the base spec's §Non-goals and §"Deferred to v2". This addendum
adds none and removes none.
