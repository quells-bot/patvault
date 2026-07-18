# Relay Slice 5 — Real-GitHub Verification Findings (2026-07-18)

Closes the last two of the base spec's §"Unverified assumptions"
(`docs/superpowers/specs/2026-07-15-relay-design.md`): that GitHub's Git
transport accepts a **chunked** `git-receive-pack` request body, and the
**status→message mapping** (what HTTP status the Git endpoints return for a
missing / inaccessible repo). The run also surfaced — and this slice fixed — a
real relay bug in the delete-only push path.

> **STATUS: RUN against real GitHub (2026-07-17/18) — both assumptions SETTLED.**
> Chunked receive-pack is accepted; the status→message mapping matches the spec's
> table. A newly-discovered delete-only-push bug was root-caused, fixed, and
> re-verified end to end.

## Provenance

- **Repo:** `quells-bot/patvault-test`, a **private** throwaway repo the
  maintainer keeps for exactly this purpose (its origin URL embeds a fine-grained
  PAT). It is a persistent fixture, not a one-off — so unlike the earlier spikes'
  credentials, it was **not** destroyed after the run; it remains the maintainer's
  to manage. No test artifacts were left behind: every scratch branch these runs
  created was deleted (the ones the pre-fix delete failed to remove were cleaned
  up directly via origin).
- **Credential:** the maintainer's fine-grained PAT, scoped to `patvault-test`
  with Contents read+write. **Never committed** — derived inline from the repo's
  origin URL at run time and passed via `SPIKE_TOKEN` / `patvault add` stdin; the
  tree was confirmed free of the token literal.
- **Run by:** Claude, in-session, at the maintainer's direction.
- **Environment:** git 2.53.0, Go 1.26.5, Linux aarch64. Relay built from
  `internal/relay` at this branch; probe is `spike/relay-real-github`.
- **Writes performed:** scratch branches pushed through the relay and deleted
  (`slice5-verify-*`, `s5del-*`, `s5delfix-*`). `main` was never modified.

## 1. Status→message mapping — SETTLED (matches the table)

The read-only probe (`spike/relay-real-github`) observed, against real GitHub's
smart-HTTP advertisement endpoint:

```
  authed upload-pack (accessible repo)             200
  unauth upload-pack (accessible repo)             401
  authed upload-pack (nonexistent repo)            404
  authed receive-pack (accessible repo)            200
```

| Spec §Errors row | Inferred status | Observed | Result |
|---|---|---|---|
| happy path (advertisement) | 200 | **200** | ✅ |
| unauthenticated private repo | (security invariant: not 200) | **401** | ✅ — the fail-before-first-byte trigger, and the "GitHub 401/403 → auth" row's basis |
| GitHub 404 (repo not found / token can't see it) | 404 | **404** (nonexistent) | ✅ — confirms `classifyStatus` 404 → `errGitHubNotFound` |

`classifyStatus` (`internal/relay/bridge.go`) is correct as written: 401/403 →
`errGitHubAuth`, 404 → `errGitHubNotFound`, 5xx → `errGitHubUnreachable`.

**Not separately observed (one repo + one read/write token available):**

- **No-access repo (403 vs 404).** GitHub hides existence: a nonexistent repo
  returned 404, and the base spec notes the Git endpoint returns 404 (not 403)
  for a private repo the token cannot see — the same existence-hiding the 404
  message already covers ("not found, or the stored token cannot see it"). Not
  separately reproduced because no second private repo outside the PAT's scope was
  on hand; the nonexistent→404 observation covers the 404 row's behavior.
- **Revoked / insufficient-scope token (401 vs 403).** Not reproduced (would
  require revoking the working token or a second read-only token). Both map to
  `errGitHubAuth` regardless, and the client action is identical ("refresh with
  'patvault add'"), so the distinction is not actionable — consistent with the
  observed unauth **401** and the push spike's Bearer **401**. The
  expired-PAT case is unreachable through the relay: `server.resolve` refuses an
  expired PAT locally (`errExpiredPAT`) before any upstream call.

## 2. Chunked receive-pack body — SETTLED (accepted)

A real `git clone`, incremental `git fetch`, and `git push` were driven through a
real `patvault relay serve` (SSH front door) pointed at `github.com`, backed by
the stored PAT:

- **Clone (v2):** succeeded; content present in the working tree.
- **Incremental fetch (v2):** succeeded.
- **Push (a new commit to a scratch branch):** **succeeded** — GitHub accepted the
  relay's **chunked** (`Transfer-Encoding: chunked`, `ContentLength = -1`)
  `git-receive-pack` request body and created the branch, returning the
  sideband-framed report-status (the PR-hint `remote:` lines). `remote-curl`'s
  chunked-for-large-pushes expectation holds on GitHub's endpoint.
- **PAT non-leak:** the injected `github_pat_…` token appeared in **no**
  client-visible output (clone content, git stderr).

**Consequence:** `pushPack`'s chunked design is confirmed; no buffering fallback
is needed. The plan's Branch B (buffer-for-Content-Length) was **not** taken —
except, narrowly, for the delete-only case below (which buffers for a different
reason: a missing client EOF, not a chunked rejection).

## 3. Delete-only push bug — FOUND, FIXED, RE-VERIFIED

The run surfaced a real relay bug that no prior test or spike had exercised over
the live streaming path:

- **Symptom:** `git push origin :refs/heads/<branch>` (a delete-only push) through
  the relay hung ~10s then failed with `patvault: github unreachable (408); safe
  to retry shortly` and `send-pack: unexpected disconnect while reading sideband
  packet`. Reproducible every time.
- **Root cause:** a delete-only push sends ref-update commands + flush and **no
  packfile**, and git does **not** half-close its write side for it. `pushPack`
  streamed the client channel to EOF to terminate the (chunked) upstream body, so
  the body never completed and GitHub timed out the request → 408. This falsified
  an **untested generalization** in the push-framing probe
  (`2026-07-16-relay-push-framing-probe.md`), which claimed "commands+flush+EOF
  and commands+flush+pack+EOF are the same code path" but only ever pushed a real
  branch (with a pack), never a delete. Buffering (plan Branch B) would not fix it
  — `io.ReadAll(in)` blocks on the same missing EOF.
- **Fix (commit `d247771`):** `pushPack` now reads the ref-update command list up
  to its flush-pkt and, if every command is a deletion (new-oid all zeros → no
  pack follows), sends the buffered commands with a known `Content-Length` instead
  of waiting for a client EOF; otherwise it streams the pack from the channel to
  EOF, chunked, byte-for-byte as before. Delete detection parses only the small
  text command list, never the pack. Guarded hermetically by a test whose client
  never EOFs (reproduces the hang against the pre-fix code).
- **Re-verified against real GitHub:** a delete-only push through the fixed relay
  **succeeded** — `- [deleted] s5delfix-…`, exit 0, ~1s (was a 10s hang), branch
  confirmed removed on the remote, relay logged `served` not `refused`.

Secondary note: before the fix the 408 was labeled `retryable` though a
delete-only push would never succeed; the fix removes the failure entirely, so the
mislabel no longer applies.

## Results table

| Assumption / check | Result |
|---|---|
| Chunked `git-receive-pack` body accepted by GitHub | **PASS** — real chunked push accepted |
| Status→message mapping (200 / 401 / 404) | **PASS** — matches the spec's table |
| Real clone + incremental fetch through the relay | **PASS** |
| PAT never reaches the client | **PASS** — 0 occurrences in client output |
| Delete-only push through the relay | **FIXED** — was 408 hang; now succeeds (commit `d247771`) |

## Conclusion

Both open assumptions are settled in the spec's favor: GitHub accepts the relay's
chunked receive-pack body, and the inferred status→message mapping matches
reality. The relay does a real clone, incremental fetch, normal push, **and**
delete push against real GitHub, with the PAT never leaking to the client. The
base spec's §"Unverified assumptions" chunked and status→message bullets are now
observed and can be marked SETTLED.

## Disposition

`quells-bot/patvault-test` and its PAT are the maintainer's persistent fixtures
and remain in place; no scratch branches were left behind. This note is the
durable record of what was observed (the run is reproducible only with the
maintainer's credentials).
