# Relay SSH Spike — Findings (2026-07-16)

Spike: `spike/relay-ssh/`. Validates the SSH-facing protocol assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` — specifically that a real
`git` client sends `GIT_PROTOCOL=version=2` as an SSH `env` request before the
`exec` request, and that the exec strings for fetch and push have the shape the
spec's `parseExec` expects.

> **STATUS: RUN (2026-07-16, revised) — all five scenarios PASS.** Every check
> below passed against the local `git` / `ssh` binaries. No credentials or
> network needed; anyone can reproduce this.

> **REVISION (2026-07-16):** the first version of this note drew three
> conclusions its own run did not support. All three are corrected below and
> called out in §Corrections. The headline decision ("require v2 for fetch") was
> never in doubt and still stands; one of the three, had it reached
> `internal/relay`, would have produced a fail-open v2 gate.

## Provenance of these results

The authoritative run is a **local, hermetic run** against the `git` and `ssh`
binaries on the development workstation. The spike binds `127.0.0.1:0`, starts
an SSH server, and drives the local `git` binary at itself — no GitHub, no
credentials, no network.

- **git:** 2.53.0
- **ssh:** OpenSSH_10.2p1 Ubuntu-2ubuntu3.4, OpenSSL 3.5.5
- **Go:** 1.26.5
- **Credentials:** none required (the server accepts any public key)
- **Reproducibility:** anyone with `git`, `ssh`, and `go` on PATH can run `go
  run ./spike/relay-ssh` and get the same PASS/FAIL result and the same exec
  strings. **The `request order` values are not portable** — see §Corrections
  item 3. Reproduce the *assertions*, not the env-request counts.

Observed output of the run:

```
PASS: fetch sends GIT_PROTOCOL=version=2 before exec
      request order = [env env env exec]
      GIT_PROTOCOL  = "version=2"
      exec          = "git-upload-pack '/owner/repo.git'"
PASS: protocol v0 fetch does not announce version=2
      GIT_PROTOCOL  = <not sent>
      request order = [env env exec]
      exec          = "git-upload-pack '/owner/repo.git'"
PASS: protocol v1 fetch announces version=1, not version=2
      GIT_PROTOCOL  = "version=1" (sent, but not version=2 —
                      a presence-only v2 gate would fail open here)
      request order = [env env env exec]
      exec          = "git-upload-pack '/owner/repo.git'"
PASS: exec path is the URL path, verbatim
      suffixed path passes through:      "git-upload-pack '/owner/repo.git'"
      unsuffixed path stays unsuffixed:  "git-upload-pack '/owner/repo'"
      space survives inside quotes:      "git-upload-pack '/owner/my repo.git'"
      apostrophe is POSIX-escaped:       "git-upload-pack '/owner/it'\\''s.git'"
PASS: push sends git-receive-pack exec
      GIT_PROTOCOL  = <not sent>
      request order = [env env exec]
      exec          = "git-receive-pack '/owner/repo.git'"

ALL CHECKS PASSED — agent-facing v2 signalling and push exec validated
```

## Results

| Scenario | Result | GIT_PROTOCOL | Exec string |
|---|---|---|---|
| Fetch v2 (protocol.version=2) | **PASS** | `"version=2"`, before the exec | `"git-upload-pack '/owner/repo.git'"` |
| Fetch v0 (protocol.version=0) | **PASS** | `<not sent>` | `"git-upload-pack '/owner/repo.git'"` |
| Fetch v1 (protocol.version=1) | **PASS** | `"version=1"` — **sent, but not v2** | `"git-upload-pack '/owner/repo.git'"` |
| Exec paths (4 URL shapes) | **PASS** | n/a | path echoed verbatim; see §Exec string shape |
| Push | **PASS** | `<not sent>` | `"git-receive-pack '/owner/repo.git'"` |

The `request order` column has been dropped from this table on purpose; it is
not a property of git. See §Corrections item 3.

The key observations:

- **GIT_PROTOCOL arrives before the exec under v2.** The relay learns the
  protocol version at the moment it handles the exec, which is what the design
  requires.
- **The v2 gate must compare the env request's VALUE, not its presence.** Git
  sends no `GIT_PROTOCOL` at all under `protocol.version=0`, but under
  `protocol.version=1` it *does* send one, carrying `version=1`. A gate keyed on
  presence admits a v1 client as if it were v2. The spec already says this
  correctly (§"Wire protocol", lines 254–257: fails fast if a request arrives
  *without* `version=2`) — implement it as written.
- **Fetch exec string:** `git-upload-pack '/owner/repo.git'` — single-quoted,
  leading `/`, `.git` suffix. Both the leading `/` and the `.git` come from the
  **request URL**, not from git; see §Corrections item 2.
- **Push exec string:** `git-receive-pack '/owner/repo.git'` — same shape.

## Corrections to the first version of this note

Recorded rather than silently edited, because the failure mode is worth keeping
in view: all three were the same mistake — generalizing from a single observed
run to a claim about `git`, where the spike's own construction supplied the very
thing being "observed."

1. **"The relay's v2 gate can distinguish v0 from v2 by the presence or absence
   of the env request — no need to parse the value." — WRONG, and fails open.**
   Git sends `GIT_PROTOCOL=version=1` under `protocol.version=1`. A presence-only
   gate admits a v1 client and pumps a v1 negotiation into the v2 stateless path.
   The original claim generalized from the single v0 data point, which the
   spike's plan had explicitly cautioned against (Task 4: assert the weaker
   property, "do not guess whether git omits the env request entirely or sends a
   different value"). It guessed, and guessed wrong.
   **Now covered by a committed check:** `scenarioFetchV1` in
   `spike/relay-ssh/main.go`, which hard-asserts `version=1` is sent and is not
   `version=2`.

2. **"git 2.53.0 appends `.git` to the repository path." — FALSE.** Git echoes
   the URL path through verbatim. The `.git` in the other exec strings comes from
   the spike's own URL, which used to be hardcoded as
   `ssh://git@%s/owner/repo.git`. The consequence for `parseExec` is unchanged —
   the spec's normalization (hazard 3, lines 218–222) already resolves these —
   but the reason is different: it must handle the suffix because the *user's
   remote URL* may or may not carry it, not because git adds it.

   This also retires the original item 3 ("no shell escaping edge cases were
   triggered"), which was true only because the spike drove a single synthetic
   path. See §Exec string shape.
   **Now covered by a committed check:** `scenarioExecPaths`, which drives four
   URL shapes and asserts each exec string verbatim. `scenario()` now takes the
   path as a parameter so the suffix is visibly the caller's choice.

3. **The recorded `request order` was workstation noise presented as a git
   property.** The original note recorded `[env env env env exec]` for v2 and
   `[env env env exec]` for v0, and built an observation on the counts ("4 env
   requests total", "3 env requests"). Those counts do not reproduce — the run
   above shows `[env env env exec]` and `[env env exec]` on the same machine, and
   under a scrubbed environment (`env -i`) the v2 case collapses to `[env exec]`
   and the v0 case to `[exec]`.

   The extra `env` requests are the **caller's** environment being forwarded per
   `/etc/ssh/ssh_config:50: SendEnv LANG LC_* COLORTERM NO_COLOR` — they vary
   with the invoking shell's locale and terminal variables and have nothing to do
   with git's protocol behavior. The only ordering fact that matters, and the one
   `gitProtocolBeforeExec()` actually asserts, is that `GIT_PROTOCOL` precedes the
   exec. The counts are noise; the original Provenance claim that anyone "can run
   and get the same result" was false for that column.

## Exec string shape — what `parseExec` is actually handed

`scenarioExecPaths` drives four URL shapes and pins each exec string verbatim:

| URL path | Exec string received |
|---|---|
| `/owner/repo.git` | `git-upload-pack '/owner/repo.git'` |
| `/owner/repo` | `git-upload-pack '/owner/repo'` |
| `/owner/my repo.git` | `git-upload-pack '/owner/my repo.git'` |
| `/owner/it's.git` | `git-upload-pack '/owner/it'\''s.git'` |

Two facts for `internal/relay/exec.go`:

- **The path is the URL's path and nothing else.** No suffix added, none
  stripped. `parseExec` must accept it with or without `.git`, and the leading
  `/` is there because the URL has one — both already handled by the spec's
  normalization.
- **Quoting is POSIX shell quoting, not "wrapped in quotes".** The apostrophe
  case comes back as `'/owner/it'\''s.git'` — close-quote, escaped quote,
  reopen-quote. Stripping the first and last quote yields `/owner/it'\''s.git`,
  which is wrong. `parseExec` needs a shell-word split.

  This vindicates the spec's hazard 1 (line 210: "strip one level of shell
  quoting rather than naive whitespace-splitting") — but note hazard 3's opening
  (line 218: "Strip the surrounding quotes") describes exactly the naive parse
  that gets this case wrong. The two hazards are in tension on the page; hazard 1
  is the correct one. Worth tightening hazard 3's wording when the relay plan is
  written, though the spec's shape check (line 223) means a mis-parse here is a
  false *rejection*, not a security hole.

The last two paths are not valid GitHub repo names (GitHub allows only
alphanumerics, `-`, `_`, `.`), so the shape check rejects them regardless. They
pin the quoting contract; they are not a claim that the relay should serve them.

## Conclusion

**The "require v2 for fetch" decision survives, unchanged.** The spike confirms:

- `GIT_PROTOCOL=version=2` arrives as an SSH `env` request **before** the exec
  request under `protocol.version=2`. The relay can capture it, forward it
  upstream as the `Git-Protocol` header, and rely on v2 stateless-pump semantics.
- Non-v2 fetches are distinguishable and the relay can fail closed — **provided
  the gate compares the value**. v0 sends nothing; v1 sends `version=1`.
  `GIT_PROTOCOL != "version=2"` is the correct test. Presence is not.
- Push is unaffected by the version gate and its exec string is captured for the
  parser.

The exec strings recorded here are real inputs `internal/relay/exec.go`'s
`parseExec` must handle, and §"Exec string shape" pins the two properties that
constrain it: the path is the URL's path verbatim, and the quoting is POSIX shell
quoting. No spec revision is required — the §"Wire protocol" v2 gate and the
§"Exec parsing" normalization both already describe the observed behavior, and
the examples at lines 210 and 232–233 (`'owner/repo'`, without leading `/` or
`.git`) are legitimate inputs rather than errors. The one wording fix worth
making is hazard 3's "strip the surrounding quotes", which contradicts hazard 1
and would mis-parse the apostrophe case.

## Follow-ups

- **Tighten spec hazard 3's wording** (line 218) so it does not describe a naive
  quote-strip; hazard 1 already says the right thing. Cosmetic — the shape check
  makes a mis-parse a false rejection, not a hole — but it is the sentence a
  reader implementing `parseExec` would follow.
- The three items in the spec's §"Unverified assumptions" (real-GitHub push,
  pack-body streaming and sideband pass-through, status→message mapping) remain
  untouched by this spike.

Everything in this note is now backed by an assertion in `spike/relay-ssh/`;
no claim here rests on an out-of-band probe.

## Disposition of spike code

Throwaway, with one exception: `serveOnce`'s request loop is the shape
`internal/relay`'s SSH server needs — accept a session channel, handle `env`
before `exec`, reject everything else, answer with `exit-status`. It is not
production code (it accepts any key, captures instead of serving, and handles
exactly one connection), but it is a working reference for the channel-request
handling the relay must implement, the same way `spike/relay-v2/pktline.go` is
the reference for `internal/relay/pktline.go`.
