# Push Framing Probe — Findings (2026-07-16)

Probe: `spike/relay-push-frame/`. Answers one question the spec left
under-specified, found while brainstorming `internal/relay`:

> **When a real git client pushes over SSH, how does the relay know where the
> client's request body ends?**

The spec's push bridge (§"Relay → GitHub", step 2) says "relay the client's
ref-update commands + packfile to `POST .../git-receive-pack`". An HTTP request
body must terminate. Over SSH git sends commands + flush + a **raw packfile**,
which is not pkt-line framed, and then waits for `report-status`. If nothing
marked the end of the pack, the relay could only find it by parsing the pack —
which would contradict the spec's central claim that "the relay does not need to
understand refs, packs, wants, or haves", and would make `bridge.go` far more
than a pump.

> **STATUS: RUN (2026-07-16) — the spec's premise HOLDS.** git half-closes its
> write side after a complete pack. No pack parsing is needed.

## Provenance

Local, hermetic, **no credentials and no network**: the probe binds
`127.0.0.1:0`, stands up an SSH server advertising an empty repo, and drives the
local `git` binary at it. Reproducible by anyone with `git`, `ssh`, and `go`:
`go run ./spike/relay-push-frame`. git 2.53.0, OpenSSH_10.2p1, Go 1.26.5.

Observed output:

```
=== client -> server ===
  command pkt: "0000000000000000000000000000000000000000 bf13b4419cf93eabd9b18d4ad9c2210a9268fdef refs/heads/main\0 report-status side-band-64k object-format=sha1 agent=git/2.53.0-Linux"
commands: 1, terminated by flush-pkt
=== after the commands' flush ===
  raw bytes read after flush: 284
  how the stream ended:       EOF
  starts with PACK magic:     true
  pack is COMPLETE:           yes — git index-pack accepted it (object count + trailing checksum valid)
```

and git's own verdict on the same run:

```
To ssh://127.0.0.1:43833/owner/repo.git
 * [new branch]      HEAD -> main
```

## Findings

- **git half-closes after the pack.** The client sends commands + flush + pack,
  then EOFs its write side while still reading the response. The relay can
  therefore `io.Copy` the SSH channel into the POST body until EOF and never look
  at a pack byte. `bridge.go` stays a pump.
- **The EOF follows a COMPLETE pack, not an abort.** This is the check that makes
  the finding trustworthy: a git that bailed out mid-pack would also produce an
  EOF, and the verdict would be a lie. The probe writes the drained bytes to a
  file and runs `git index-pack` on them, which validates the object count and
  the trailing checksum — it accepted the pack. The push then succeeded from
  git's point of view.
- **A sideband-framed response is mandatory when the client asks for it.** The
  client's command pkt requested `side-band-64k`. An unframed `report-status`
  earns `send-pack: protocol error: bad band #117` and `fatal: the remote end
  hung up unexpectedly` — observed on the first run of this probe, before the
  reply was framed on band 1. This costs the relay nothing (the client's
  capability list is forwarded verbatim to GitHub, so GitHub frames the reply and
  the relay pumps it back untouched), but it means **sideband pass-through is not
  optional decoration** — get it wrong and push breaks outright.

## Consequences for `internal/relay/bridge.go`

- Push body = `io.Copy(postBody, sshChannel)` until EOF. No pack parser, no
  object counting, no length prefix.
- This also subsumes the relay-push spike's "a delete-only push sends no pack"
  caveat: the bridge never distinguishes the cases. Commands + flush + EOF and
  commands + flush + pack + EOF are the same code path.
- The POST body length is unknown up front, so it goes out with
  `Transfer-Encoding: chunked` (Go's `http.Client` does this when
  `ContentLength` is unset). **Unverified:** that GitHub's receive-pack endpoint
  accepts a chunked request body. git's own `remote-curl` uses chunked for large
  pushes, which is good reason to expect it, but this probe never touched GitHub
  and the live-fire repo and PAT have since been destroyed. See §Follow-ups.

## Not covered

- **Real GitHub.** This probe's upstream is a fake server in-process; it proves
  what the *client* does, not what GitHub accepts. The chunked-body question
  above is the one live gap it opens.
- **Large packs.** 284 bytes, one commit. Streaming behavior under a pack big
  enough to exercise flow control and backpressure is untested.
- **Fetch.** Only the push direction was probed. The fetch pump reads client
  commands up to a flush and is already covered by the v2 spike.

## Follow-ups

- Confirm GitHub accepts a chunked receive-pack request body. Cheap to fold into
  the end-to-end test against real GitHub rather than standing up another spike;
  if it is rejected, the bridge must buffer the pack to compute a
  `Content-Length`, which reintroduces the "stream, never buffer" tension the
  spec calls out.

## Disposition of probe code

Throwaway, but keep until `bridge.go` exists: the `handlePush` sequence
(advertise → read commands to flush → drain to EOF → sideband-framed
report-status) is the exact shape the relay's push path implements, and it is a
working local upstream to test against.
