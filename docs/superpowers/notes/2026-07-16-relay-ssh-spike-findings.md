# Relay SSH Spike — Findings (2026-07-16)

Spike: `spike/relay-ssh/`. Validates the SSH-facing protocol assumptions in
`docs/superpowers/specs/2026-07-15-relay-design.md` — specifically that a real
`git` client sends `GIT_PROTOCOL=version=2` as an SSH `env` request before the
`exec` request, and that the exec strings for fetch and push have the shape the
spec's `parseExec` expects.

> **STATUS: RUN (2026-07-16) — all three scenarios PASS.** Every check below
> passed against the local `git` / `ssh` binaries. No credentials or network
> needed; anyone can reproduce this.

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
  run ./spike/relay-ssh` and get the same result.

Observed output of the run:

```
PASS: fetch sends GIT_PROTOCOL=version=2 before exec
      request order = [env env env env exec]
      GIT_PROTOCOL  = "version=2"
      exec          = "git-upload-pack '/owner/repo.git'"
PASS: protocol v0 fetch does not announce version=2
      GIT_PROTOCOL  = <not sent>
      request order = [env env env exec]
      exec          = "git-upload-pack '/owner/repo.git'"
PASS: push sends git-receive-pack exec
      GIT_PROTOCOL  = <not sent>
      request order = [env env env exec]
      exec          = "git-receive-pack '/owner/repo.git'"

ALL CHECKS PASSED — agent-facing v2 signalling and push exec validated
```

## Results

| Scenario | Result | Request order | GIT_PROTOCOL | Exec string |
|---|---|---|---|---|
| Fetch v2 (protocol.version=2) | **PASS** | `[env env env env exec]` | `"version=2"` | `"git-upload-pack '/owner/repo.git'"` |
| Fetch v0 (protocol.version=0) | **PASS** | `[env env env exec]` | `<not sent>` | `"git-upload-pack '/owner/repo.git'"` |
| Push | **PASS** | `[env env env exec]` | `<not sent>` | `"git-receive-pack '/owner/repo.git'"` |

The key observations:

- **GIT_PROTOCOL is sent only under v2.** Under `protocol.version=2`, the
  `GIT_PROTOCOL=version=2` env request arrives before the exec request (4 env
  requests total). Under `protocol.version=0`, git omits `GIT_PROTOCOL`
  entirely (3 env requests). The relay's v2 gate can therefore distinguish the
  two by the presence or absence of the env request — no need to parse the
  value.
- **Fetch exec string:** `git-upload-pack '/owner/repo.git'` — single-quoted,
  **leading `/`**, **with `.git`** suffix.

- **Push exec string:** `git-receive-pack '/owner/repo.git'` — single-quoted,
  **leading `/`**, **with `.git`** suffix.
- **The `.git` suffix is present in both cases.** The spec's example at line
  210 shows `'owner/repo'` without `.git`; the actual binary sends
  `'/owner/repo.git'` for both fetch and push.

## Surprises / deviations from the spec

The spec's "Exec parsing" section (`docs/superpowers/specs/2026-07-15-relay-design.md`,
§"Exec parsing", lines 210–226) makes several assumptions that the spike
refines:

1. **`.git` suffix is always present.** The spec's example at line 210
   (`git-upload-pack 'owner/repo'`) and the mapping at lines 232–233 both omit
   `.git`. In reality, git 2.53.0 appends `.git` to the repository path in both
   `git-upload-pack` and `git-receive-pack` exec strings. The spec's
   normalization path (line 220: `urlparse.NormalizePath` strips trailing
   `.git`) already handles this — the surprise is only that the documentation
   examples were incomplete, not that the parser is wrong.

2. **Leading `/` is present on both fetch and push.** The spec's normalization
   (line 218) correctly strips a leading `/` when present, noting
   `'/owner/repo'` as the example. The spike confirms both `git-upload-pack`
   and `git-receive-pack` send `'/owner/repo.git'` with a leading `/` — there
   is no fetch/push asymmetry in this regard. The normalization handles both.

3. **Single-quoting is confirmed.** Both exec strings arrive single-quoted, as
   the spec assumes. No shell escaping edge cases (spaces, apostrophes, or
   special characters in the path) were triggered by this run — the test repo
   name is the synthetic `owner/repo`.

4. **GIT_PROTOCOL absent under v0 is observed, not asserted-but-not-captured.**
   The spike prints `GIT_PROTOCOL = <not sent>` explicitly when the env request
   is absent, so this is a recorded observation, not an inference from the
   absence of a log line.

## Conclusion

**The "require v2 for fetch" decision survives.** The spike confirms that:

- `GIT_PROTOCOL=version=2` arrives as an SSH `env` request **before** the exec
  request under `protocol.version=2`. The relay can capture it, forward it
  upstream as the `Git-Protocol` header, and rely on the v2 stateless-pump
  semantics.
- Under `protocol.version=0`, `GIT_PROTOCOL` is absent. The relay can fail
  closed on a v0 fetch with no ambiguity.
- Push is unaffected by the version gate and its exec string is captured for
  the parser.

The exec strings recorded here are the exact inputs `internal/relay/exec.go`'s
`parseExec` must handle. The spec's `NormalizePath` pipeline already covers the
observed shape `'/owner/repo.git'`; the only spec revision needed is to update
the examples in the "Exec parsing" section to reflect the `.git` suffix.

## Disposition of spike code

Throwaway, with one exception: `serveOnce`'s request loop is the shape
`internal/relay`'s SSH server needs — accept a session channel, handle `env`
before `exec`, reject everything else, answer with `exit-status`. It is not
production code (it accepts any key, captures instead of serving, and handles
exactly one connection), but it is a working reference for the channel-request
handling the relay must implement, the same way `spike/relay-v2/pktline.go` is
the reference for `internal/relay/pktline.go`.
