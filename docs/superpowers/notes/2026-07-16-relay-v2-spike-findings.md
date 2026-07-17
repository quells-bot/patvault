# Relay v2 Spike — Findings (2026-07-16)

Spike: `spike/relay-v2/`. Validates the v2 smart-HTTP assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` against real GitHub.

> **STATUS: RUN against real GitHub (2026-07-16) — v2 assumptions hold, with
> one FAIL.** Every protocol assumption below passed against a live private
> repo. The exception is the auth scheme: `Authorization: Bearer` is **rejected**
> by GitHub's Git transport and the relay must use HTTP Basic instead. The spec
> has been corrected (`2026-07-15-relay-design.md`); see Surprises below.

## Provenance of these results

The authoritative run is a **live run against a private repo, executed by the
repo owner** with a fine-grained PAT; the output pasted below is theirs. It was
not independently reproduced afterwards (the PAT was deleted immediately after,
as intended). An earlier run against a **public** repo is what surfaced the
Bearer failure, but its protocol PASSes were not evidence of anything: a public
repo serves the advertisement to unauthenticated requests, so those checks would
have passed with no token at all. Only the private-repo run exercises the
credential.

Observed output of the authoritative run:

    PASS: advertisement (upload-pack v2)
    PASS: no-auth rejected
          unauthenticated status = 401
    PASS: ls-refs round-trip
          HEAD = b42646572dd128d093a9d68380ff90fa914d6d62
    PASS: fetch round-trip
          received packfile section header

    ALL CHECKS PASSED — v2 protocol assumptions validated

## Also verified (offline)

- `go build ./spike/relay-v2/` — passes.
- `go vet ./spike/relay-v2/` — clean.
- `go test ./spike/relay-v2/` — passes (pkt-line encode/decode round-trip and
  invalid-length handling).

## Results

| Assumption (from spec) | Result | Notes |
|---|---|---|
| `info/refs` prefixes a `# service=git-upload-pack` pkt-line + flush to strip | PASS | `checkAdvertisement()` hard-asserts the banner prefix and the following flush; both held. The spike does not echo the banner, so its literal bytes are asserted-but-not-captured. |
| Advertisement is v2 (`version 2`) with `ls-refs` + `fetch` capabilities when `Git-Protocol: version=2` sent | PASS | First advertisement line was `version 2` and both `ls-refs` and `fetch` were present, else the check would have failed. The spike asserts presence without printing the full capability list, so the other advertised capabilities were not recorded. |
| Unauthenticated advertisement GET is rejected, not 200 (fail-before-first-byte trigger point) | PASS | Observed status **401** against the private repo. This is the row that required a private repo, and it is the trigger point the relay's fail-before-first-byte invariant keys off. |
| `ls-refs` command POST returns refs (single self-contained request) | PASS | HEAD = `b42646572dd128d093a9d68380ff90fa914d6d62`. One self-contained POST, no negotiation state carried across requests — the v2 stateless-pump premise holds. |
| `fetch` command POST (want/deepen/done) returns a `packfile` section | PASS | The decisive check. A `packfile` section header came back. `fetchPack()` skips non-matching sections without logging them, so the **section order was not captured** — whether `shallow-info` preceded `packfile` under `deepen 1` remains unobserved. Worth printing if the spike is ever re-run. |
| PAT injection via `Authorization: Bearer` accepted on GET + POST | **FAIL** | GitHub answers **401** to `Bearer` on the Git transport. HTTP Basic (`x-access-token:<PAT>`) works and is what the passing run used. See Surprises. |

## How to run it

    SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2

- `SPIKE_REPO` must be a **private** repo. `SPIKE_PUBLIC=1` looks like it skips
  only the no-auth check, but against a public repo *every* check passes without
  a valid token, so the run proves nothing about auth (see Surprises).
- `SPIKE_TOKEN` must be a fine-grained PAT with Contents access to `SPIKE_REPO`.

## Surprises / deviations from the spec

**GitHub's Git transport requires HTTP Basic, not Bearer.** The spec assumed the
relay would inject `Authorization: Bearer <PAT>` upstream. Against
`https://github.com/<owner>/<repo>.git`, that returns **401** — including for a
fine-grained PAT that `api.github.com/user` accepts (200) on the same token in
the same session. The scheme is the failure, not the credential. Evidence, all
against one public repo with one valid PAT:

| Request | Status |
|---|---|
| `api.github.com/user`, `Authorization: Bearer <PAT>` | 200 |
| `info/refs?service=git-upload-pack`, `Authorization: Bearer <PAT>` | **401** |
| `info/refs?service=git-upload-pack`, Basic `x-access-token:<PAT>` | 200 |
| `info/refs?service=git-upload-pack`, no auth | 200 (repo is public) |

Bearer is honored on `api.github.com` but not on the Git endpoints. The fix is
`Authorization: Basic base64("x-access-token:<PAT>")`; the username half is
ignored for a PAT, and `x-access-token` is the conventional placeholder.

**Spec sections revised** (both done, 2026-07-16): `2026-07-15-relay-design.md`
§"Relay → GitHub: the pkt-line ↔ HTTPS bridge" (the `remote-curl` injection
description) and the `git push` sequence diagram. `internal/relay/bridge.go` must
use Basic when it is written; `internal/github` is unaffected, since it talks to
the REST API, where Bearer is correct.

Note that a **public** repo cannot surface this class of bug on its own: it
serves the advertisement to unauthenticated requests, so the auth path is never
actually exercised and every protocol check passes regardless of the token. The
`SPIKE_PUBLIC=1` escape hatch trades away more than the one no-auth check it
appears to skip.

No deviations in framing, section structure, or content-types: the banner+flush
prefix, the `version 2` advertisement, and the single-POST `ls-refs` / `fetch`
round-trips all matched the spec as written.

## Conclusion

**The v2 protocol assumptions are de-risked; the auth assumption was wrong and
is now fixed in the spec.** The relay's core premise — that v2 lets each command
be a self-contained, stateless POST that the relay can pump without understanding
refs, packs, wants, or haves — holds against real GitHub. So does the
fail-before-first-byte trigger point: an unauthenticated advertisement GET on a
private repo returns 401, before any git data is emitted to the agent.

`internal/relay` can proceed, with two conditions:

1. Use HTTP Basic for upstream PAT injection. This is the one thing the spike
   falsified, and it would have been a live-fire 401 in the bridge otherwise.
2. Do not treat the fetch **section order** as known. The spike confirmed a
   `packfile` section arrives but discarded what preceded it, so whether
   `shallow-info` leads under `deepen 1` is still unobserved. The bridge as
   specced does not care (it pumps framed pkt-lines without interpreting
   sections), but any code that comes to depend on section order needs its own
   check first.

## Disposition of spike code

Keep as reference for `internal/relay/pktline.go`. The `spike/relay-v2/pktline.go`
helpers are the direct source for the production `internal/relay/pktline.go`
implementation. (This disposition stands regardless of the live-run outcome;
a FAIL would change the spec, not the value of the pkt-line helpers.)
