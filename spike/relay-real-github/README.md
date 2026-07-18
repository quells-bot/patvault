# relay-real-github — slice-5 real-GitHub verification probe

Throwaway. Closes the last two of the relay spec's §"Unverified assumptions"
(`docs/superpowers/specs/2026-07-15-relay-design.md`):

1. **status→message mapping** — what HTTP status GitHub's Git transport returns
   for a missing / inaccessible repo. This probe observes it (read-only).
2. **chunked receive-pack body** — confirmed by the manual relay e2e push below,
   not by this probe (so the probe never builds a pack).

## Credentials — throwaway only

Use a **fresh private repo** and a **fine-grained PAT** you will delete right
after. Nothing here is reproducible from a clean checkout without them; the
slice-5 findings note is the durable evidence. Never commit the token.

## Run the probe (read-only)

    SPIKE_TOKEN=<fine-grained PAT> SPIKE_REPO=owner/throwaway-private go run ./spike/relay-real-github

Optional, each skipped if unset:

    SPIKE_MISSING_REPO=owner/does-not-exist-$(date +%s)   # nonexistent -> ?
    SPIKE_NOACCESS_REPO=owner/some-other-private          # real repo the token can't see
    SPIKE_READONLY_TOKEN=<read-only PAT>                  # insufficient-scope receive-pack

Paste the printed "observed statuses" block into the findings note.

## Run the manual relay e2e (confirms chunked + happy path)

See the slice-5 plan, Task 2. In brief: `patvault add` the repo+PAT on a
throwaway config, `patvault relay add-key` your agent key, `patvault relay serve
--listen 127.0.0.1:2222`, then in another shell `git clone` / `fetch` / `push`
via `ssh://git@127.0.0.1:2222/owner/throwaway-private.git`. A successful push
confirms GitHub accepts the relay's chunked receive-pack body.

## After the run

Delete the PAT and the throwaway repo — or, if it is a persistent private
fixture you keep for this purpose, leave it and just clean up any scratch
branches the run created. Either way, confirm no token literal is in the tree.
