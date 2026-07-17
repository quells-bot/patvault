# relay-v2 spike (throwaway)

Validates patvault's relay v2 protocol assumptions against **real GitHub**
before any relay/SSH code exists. Not part of the shipped binary.

## Run

    SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2

Add `SPIKE_PUSH=1` to also run the push **write** checks (7–8 below). Without
it they are skipped, so no run mutates a repo by accident.

- Use a **private** repo so the no-auth (401) check is meaningful; otherwise
  set `SPIKE_PUBLIC=1` to skip it. Against a public repo every auth check
  passes with no token at all, so the run proves nothing about auth.
- The token must be a fine-grained PAT with Contents access to `SPIKE_REPO`.
  For `SPIKE_PUSH=1` it needs Contents **write**.
- Pass the token via the environment. Do not embed it in a remote URL: that
  persists it in `.git/config` and echoes it from `git remote -v`.

## What it checks

Fetch (`main.go`):

1. `info/refs?service=git-upload-pack` advertisement: `# service=` banner +
   flush to strip, then `version 2` and `ls-refs`/`fetch` capabilities.
2. Unauthenticated advertisement GET is rejected (not 200; 401/404) — the point
   the relay's fail-before-first-byte invariant keys off.
3. `ls-refs` command POST returns refs; HEAD oid extracted.
4. `fetch` command POST (want HEAD, `deepen 1`, `done`) returns a `packfile`
   section.

Push (`push.go`) — tier 1, read-only:

5. `info/refs?service=git-receive-pack` advertisement: the same `# service=`
   banner + flush, and a classic ref-list rather than a v2 advertisement even
   though `Git-Protocol: version=2` is sent (push ignores the version gate).
6. Auth scheme on the receive-pack endpoint: Basic must be 200 and
   unauthenticated must not be. Bearer's status is printed, not asserted — the
   relay uses Basic regardless.

Push (`push.go`) — tier 2, **writes**, needs `SPIKE_PUSH=1`:

7. A real push: clone, empty commit, pack just that commit, POST commands+pack,
   parse `report-status`.
8. A delete of the scratch ref — a commands-only request with **no pack**,
   which the bridge must not assume away.

Findings: `docs/superpowers/notes/2026-07-16-relay-push-spike-findings.md`.

`pktline.go` here is the reference the eventual `internal/relay/pktline.go`
mirrors.