# Relay v2 Spike — Findings (2026-07-16)

Spike: `spike/relay-v2/`. Validates the v2 smart-HTTP assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` against real GitHub.

> **STATUS: PENDING — the spike has NOT been run against real GitHub yet.**
> No live credentials were available in this environment, so none of the
> network assumptions below have been confirmed. The code builds, `go vet` is
> clean, and the offline pkt-line unit tests pass — but that only exercises the
> deterministic framing helpers, not the actual GitHub round-trips. Every
> `PENDING` row is an unverified prediction until someone runs the spike and
> records the observed output. Do **not** treat this note as evidence that the
> v2 protocol assumptions hold.

## What has actually been verified

- `go build ./spike/relay-v2/` — passes.
- `go vet ./spike/relay-v2/` — clean.
- `go test ./spike/relay-v2/` — passes (pkt-line encode/decode round-trip and
  invalid-length handling). This is the **only** offline/deterministic part.

## What is still PENDING (requires a live run)

| Assumption (from spec) | Result | Notes |
|---|---|---|
| `info/refs` prefixes a `# service=git-upload-pack` pkt-line + flush to strip | PENDING | Code in `checkAdvertisement()` asserts this, but GitHub's actual advertisement framing under `Git-Protocol: version=2` is unconfirmed. Paste the observed banner after running. |
| Advertisement is v2 (`version 2`) with `ls-refs` + `fetch` capabilities when `Git-Protocol: version=2` sent | PENDING | Unconfirmed against real GitHub. Record the observed first line and capability list. |
| Unauthenticated advertisement GET is rejected, not 200 (fail-before-first-byte trigger point) | PENDING | Requires a real **private** repo. Record the observed status (expect 401/404). Not meaningful against a public repo — use `SPIKE_PUBLIC=1` to skip only if you accept losing this check. |
| `ls-refs` command POST returns refs (single self-contained request) | PENDING | Record the extracted HEAD oid. |
| `fetch` command POST (want/deepen/done) returns a `packfile` section | PENDING | Record which sections come back (e.g. `shallow-info` before `packfile`). This is the decisive check. |
| PAT injection via `Authorization: Bearer` accepted on GET + POST | PENDING | Confirmed only indirectly (a passing advertisement/ls-refs/fetch implies the PAT was accepted). Record explicitly. |

Result legend: **PENDING** = not yet run; replace with **PASS** / **FAIL** and
fill Notes from the actual output once the spike has been executed.

## How to run it

    SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2

- `SPIKE_REPO` must be a **private** repo so the no-auth (401) check is
  meaningful; otherwise set `SPIKE_PUBLIC=1` to skip that one check.
- `SPIKE_TOKEN` must be a fine-grained PAT with Contents access to `SPIKE_REPO`.

After running, replace each `PENDING` above with the observed `PASS`/`FAIL`,
paste the real banner / capabilities / HEAD oid / sections into the Notes
column, and fill in the two sections below.

## Surprises / deviations from the spec

_PENDING — fill in after the live run._ Note any unexpected section order,
header requirement, content-type, or status code. If an assumption FAILS,
record the exact spec section that needs revision before implementation.

## Conclusion

_PENDING — cannot be drawn until the spike is run against real GitHub._ The
code is structurally complete, but "structurally complete" is not "validated."
Do not proceed to implement `internal/relay` on the strength of this note
alone: run the spike, confirm every row above flips to PASS, and only then
treat the v2 assumptions as de-risked. If any row is FAIL, revise the relevant
spec section first.

## Disposition of spike code

Keep as reference for `internal/relay/pktline.go`. The `spike/relay-v2/pktline.go`
helpers are the direct source for the production `internal/relay/pktline.go`
implementation. (This disposition stands regardless of the live-run outcome;
a FAIL would change the spec, not the value of the pkt-line helpers.)
