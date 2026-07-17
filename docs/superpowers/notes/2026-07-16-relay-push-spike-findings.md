# Relay Push Spike — Findings (2026-07-16)

Spike: `spike/relay-v2/push.go`. Closes the first of the spec's §"Unverified
assumptions" (`docs/superpowers/specs/2026-07-15-relay-design.md`, lines
518–525): **push against real GitHub was untested.** The sibling note
`2026-07-16-relay-v2-spike-findings.md` covers the fetch half of the same
program; this one covers push only.

> **STATUS: RUN against real GitHub (2026-07-16) — all five checks PASS.**
> Tier 1 (read-only) and tier 2 (a real push) both ran against a live **private**
> repo. No spec assumption was falsified.

## Provenance of these results

- **Repo:** `quells-bot/patvault-test`, a throwaway **private** repo, confirmed
  `"private": true` with `push: true` permission before the run. Private matters:
  per the v2 note, a public repo serves the advertisement unauthenticated, so
  every auth check passes with no token and proves nothing.
- **Credential:** a fine-grained PAT supplied by the repo owner. **Not
  reproducible without one** — unlike `spike/relay-ssh`, nobody can re-run this
  from a clean checkout. The output below is the only evidence.
- **Run by:** Claude, in-session, at the owner's direction — not by the owner
  themselves (the v2 note's run was the owner's). The PAT and the repo were
  destroyed afterwards; see §Credential and repo disposition.
- **Writes performed:** one empty commit pushed to a scratch ref
  (`refs/heads/spike-push-<unix>`), then deleted. Verified afterwards via the
  refs API that only `refs/heads/main` remains, at its original SHA
  `b324708d6b61` — the push left nothing behind.

Observed output (tier 1 + tier 2; the fetch checks that precede it are the v2
note's business and are elided):

```
PASS: advertisement (receive-pack)
      banner        = "# service=git-receive-pack"
      first ref     = "b324708d6b615c830529b308c952e1af278a86ed refs/heads/main"
      capabilities  = report-status report-status-v2 delete-refs side-band-64k ofs-delta atomic object-format=sha1 quiet agent=github/spokes-receive-pack-acac8763c60f636c44baaf5c3887895cf5f55c30 session-id=BA39:2BB422:5B3CDE3:5D65522:6A59AF56 push-options
PASS: receive-pack auth scheme
      none          = 401
      Bearer        = 401 (recorded, not asserted)
      Basic         = 200
PASS: push round-trip (report-status)
      pushed        = 90e6f7d62f97 -> refs/heads/spike-push-1784262487
      pack size     = 193 bytes
      report-status = [unpack ok ok refs/heads/spike-push-1784262487]
PASS: push delete-ref round-trip (no pack)
      deleted       = refs/heads/spike-push-1784262487
      report-status = [unpack ok ok refs/heads/spike-push-1784262487]
```

## Results

| Assumption (from spec) | Result | Notes |
|---|---|---|
| receive-pack `info/refs` prefixes a `# service=git-receive-pack` banner + flush to strip | **PASS** | Identical framing to upload-pack. The relay's existing strip logic applies unchanged. |
| Push is unaffected by the v2 gate — receive-pack ignores `Git-Protocol: version=2` | **PASS** | The request sent the header anyway; the reply was a classic ref-list advertisement, not `version 2`. The check hard-fails if a v2 advertisement ever comes back. |
| Upstream PAT injection works on the receive-pack endpoint | **PASS** | Basic → **200**. The v2 note's Basic-not-Bearer correction holds on this endpoint too. |
| Unauthenticated push endpoint is rejected | **PASS** | **401**, matching upload-pack. The fail-before-first-byte trigger point is the same for push. |
| commands+pack POST returns a `report-status` | **PASS** | `unpack ok` + `ok refs/heads/<ref>`. A 193-byte pack carrying one empty commit. |
| A delete-only request (no pack) round-trips | **PASS** | Same report-status shape with **zero pack bytes** sent. |

## Key observations

- **Push framing is the same as fetch.** Banner, flush, then the payload. Nothing
  about receive-pack requires a second code path in the relay's advertisement
  handling.
- **`Bearer` is 401 here too.** Recorded, not asserted — the relay uses Basic
  regardless, so pinning GitHub's rejection of a scheme we do not use would buy
  nothing and would fail spuriously if GitHub ever widened Bearer support. The
  fact is consistent with the v2 note's upload-pack finding, which is mild
  evidence the behavior is transport-wide rather than endpoint-specific, but this
  spike tested two endpoints, not "the transport".
- **A pack does not always follow the commands.** The delete-ref request sent
  commands + flush and nothing else, and GitHub answered normally. Any bridge
  code that assumes commands are always followed by pack bytes will hang or
  mis-frame on a `git push --delete`. This was free to observe and is the most
  likely thing to get wrong in `internal/relay/bridge.go`.
- **`report-status-v2` is a receive-pack capability, not wire protocol v2.**
  GitHub advertises both `report-status` and `report-status-v2` in the same list
  as `object-format=sha1`. The name collides with the v2 the spec's gate talks
  about; they are unrelated. Worth spelling out before someone wires the v2 gate
  to a receive-pack capability.

## Not covered (do not mistake this for broader coverage)

- **Sideband.** `side-band-64k` is advertised but was deliberately **not**
  requested, so the report-status came back as plain pkt-lines. Sideband
  pass-through remains the spec's second unverified assumption, untouched.
- **Pack streaming.** The pack was 193 bytes and sent as one buffered body. The
  stream-never-buffer rule is unexercised.
- **The empty-repo first push.** `patvault-test` already had an initial commit,
  so the zero-refs `capabilities^{}` advertisement was never seen.
- **The rejection path.** Every command succeeded. `report-status`'s `ng` line, a
  non-fast-forward rejection, and a push to a protected branch are all unobserved
  — the parser has only ever seen success.
- **The status→message mapping** (spec §Errors) — still the third unverified
  assumption, untouched. This run only ever saw 200 and 401.
- **Capability list stability.** The `agent=` and `session-id=` values above are
  per-run and per-host; `session-id` differed between two runs minutes apart. They
  are recorded as observed output, **not** as a contract. Nothing should parse
  them. (This is the same trap as the relay-ssh note's env-request counts: a value
  that appears in the output but is not a property of the system under test.)

## Conclusion

**Push support can proceed; nothing in the spec's push story was falsified.** The
receive-pack advertisement framing matches upload-pack, the Basic auth scheme
carries over to the push endpoint, and the commands+pack → report-status
round-trip works against real GitHub exactly as specced.

Two things for `internal/relay/bridge.go` when it is written:

1. **Do not assume a pack follows the commands.** A delete-only push legitimately
   sends none. Observed, not inferred.
2. **The report-status parser has only seen success.** `unpack ok` / `ok <ref>` is
   all this run produced. The `ng` rejection path is unobserved and needs its own
   coverage — a stub upstream is the cheap way, since provoking a real rejection
   costs another live repo.

The spec's §"Unverified assumptions" first bullet is now settled and has been
updated to cite this note.

## Credential and repo disposition

Both the PAT and `quells-bot/patvault-test` were **destroyed after this run**, as
intended — the same ending as the v2 spike's credential. A future reader will not
find that repo; its absence is expected, not a broken link.

This is why the output block above is the only evidence and why §Provenance says
the run is not reproducible: re-running it means standing up a new private repo
and a new PAT. Weigh that before treating any line here as re-checkable.

The token was passed to the spike via `SPIKE_TOKEN` and appears in no committed
file (verified by scanning the tree for the literal value and for PAT-shaped
strings before the commit). It reached this session embedded in the test repo's
`remote.origin.url`, which persists a token in `.git/config` and echoes it from
`git remote -v` — worth avoiding for a longer-lived credential, moot for one
deleted immediately after.

## Disposition of spike code

Same as the v2 spike: keep as reference. `push.go`'s receive-pack request
construction (command pkt-line, NUL-separated capabilities, flush, raw pack) is
the direct shape `internal/relay/bridge.go` needs for the push direction, and the
tier-1/tier-2 split is worth preserving — the read-only tier is the part anyone
with a private repo can re-run cheaply.
