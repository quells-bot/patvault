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