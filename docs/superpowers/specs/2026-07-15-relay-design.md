# Patvault: Credential-Injecting Relay

Status: proposed (design finalized)
Date: 2026-07-15
Updated: 2026-07-16
Relationship: a v2 architecture for patvault. The existing credential-helper
mode (git ↔ `patvault credential get`) remains valid and can coexist; this spec
adds a relay mode for the case where the *caller must never hold the token*.

## Overview

The credential-helper design has an unavoidable limitation: git — and therefore
whatever process invokes git — ends up holding the plaintext PAT. When that
process is a coding agent that can run arbitrary commands, "can the agent leak
the token" reduces to "can the agent run a command," which is always true. No
amount of at-rest encryption changes this, because the token is handed to the
caller by design.

This spec inverts the boundary. Instead of handing the token to git, patvault
becomes a **credential-injecting transport relay**: the agent's git speaks to
the relay over SSH, the relay speaks to GitHub over HTTPS and injects the PAT
into the upstream request. The token lives and dies inside the relay process
and on the TLS wire to GitHub. The agent's process, environment, config, and
disk never contain it.

The design decouples two identities that the helper model conflates:

- **Agent → relay** is authenticated by an **SSH key** — a purely local
  credential that proves *which agent* and is useless anywhere except against
  this relay.
- **Relay → GitHub** is authenticated by a short-lived, single-repo **PAT** held
  only by the relay.

Consequences: onboarding or revoking an agent is a local operation (add/remove a
public key), with no GitHub interaction; and a compromised agent cannot
exfiltrate a reusable GitHub credential, because none ever crosses the boundary.

## Goals

- The agent never holds, sees, or can read a GitHub PAT.
- Agent-to-relay authentication uses SSH public keys (local, revocable, not a
  GitHub credential).
- The relay holds only **pre-provisioned, self-expiring, single-repo PATs** —
  the existing encrypted patvault store, unchanged.
- Support `git clone`/`fetch` (read) and `git push` (write) transparently.
- Run the relay on a macOS host, with the agent in a UTM guest VM reaching it
  over a private host-only network at a stable IP.

## Non-goals

- **No token minting or renewal.** The relay never calls GitHub's token API. A
  GitHub App installation-token approach was explicitly rejected: an App private
  key is a standing capability to mint credentials *forever*, which is a worse
  thing to hold than the credentials themselves. Expired tokens are refreshed
  manually on the host (see "Expiry as a feature").
- **No policy layer in v1** — per-key→repo scoping, approval-on-push,
  force-push/deletion denial, and audit logging are deferred to v2. See
  "Deferred to v2."
- **No change to the encryption/derivation scheme** for stored tokens.
- **No git wire protocol v0 fetch bridging.** v1 requires protocol v2 for
  fetches (see "Wire protocol: require v2 for fetch"). Supporting v0 fetches
  would mean building a stateful↔stateless negotiation engine, which is
  deliberately out of scope.
- **No bundled front-end.** v1 ships `patvault relay serve`, a foreground
  server. A menu-bar / GUI wrapper (for explicit lifecycle and one-click token
  refresh) is a possible later addition, specced separately; the relay core is
  a headless package so any front-end is additive.

## Prior art

The *category* — a proxy that mediates between a developer's git and an upstream
forge — is not novel. Two neighbors bound our position:

- **Teleport's Git proxy** (goteleport.com) is the closest cousin and shares our
  *shape*: the developer authenticates to the proxy with a local identity, the
  proxy forwards to GitHub under a separately-held identity, and every command
  is audit-logged. But the mechanism is the inverse of ours where it matters: it
  is **enterprise-only** (Teleport Enterprise + GitHub Enterprise Cloud),
  requires **GitHub-side configuration** (an OAuth app plus registering
  Teleport's CA in the org's SSH certificate authorities), and authenticates
  upstream with **short-lived SSH certificates minted by Teleport's CA** — a
  *standing minting capability*, precisely the thing our non-goals reject.
  Teleport is the org-scale access-control plane we deliberately argued against.

- **FINOS git-proxy** (github.com/finos/git-proxy) sits between developer and
  remote and intercepts **pushes** for approval/policy/scanning. That is
  essentially our **deferred v2** (approval-on-push, force-push/deletion denial,
  protected branches), not credential isolation; its credential model leans on
  the client's own keys / SSH agent-forwarding, so the developer still holds
  credentials. It is a multi-user, compliance-oriented framework.

Neither occupies our niche: **single-user, single-host, local-first; zero
GitHub-side config; zero minting capability; reusing a tiny encrypted
single-repo-PAT store; threat-modeled around a compromised local coding agent.**
The neighbors also validate two choices — the identity split is proven at scale,
and our rejection of token minting is the deliberate inverse of Teleport's core
mechanism.

## Threat model

What the relay closes:

- **Agent compromise (the target case).** An attacker who fully owns the guest
  VM gets the agent's SSH key and can drive git *while the relay is running and
  reachable*, doing only what that key is authorized for. They **cannot**
  exfiltrate a portable GitHub credential — nothing reusable crosses the
  boundary. Revocation is deleting one line from the relay's allowlist, with no
  GitHub involvement. This converts a portable, offline, durable secret (a PAT
  the agent holds) into an online, proxied, revocable, non-portable capability.

- **At-rest exposure in headless environments.** Because the secret-holder is
  now the macOS host, the master key lives in the **macOS Keychain**, not the
  weaker keychainless `master.key` file that headless agent environments would
  otherwise force. The guest holds nothing to protect.

The concentrated risk it introduces:

- **Relay compromise.** An attacker who owns the host gets the encrypted store
  and, via the Keychain, the PATs. This is mitigated by (a) holding only
  single-repo, self-expiring tokens — no minting capability, so the blast radius
  is bounded and time-limited; (b) the relay being a small, auditable surface;
  and (c) the network exposure being confined to the host-only interface.

The boundary is a genuine machine boundary. A compromised agent in the guest can
reach only the relay's **socket** — never its process memory, its database, or
the Keychain, which live on a different machine (VM escape out of scope).

### Known limitation: flat authorization (v1)

The agent-compromise mitigation above says a compromised key can do "only what
that key is authorized for" — but in v1 **every authorized key is authorized for
everything**: any key in the allowlist may reach any repo that has a stored PAT.
So a single compromised agent key's blast radius is *all* stored repos, not just
the one that agent legitimately works on. The relay narrows the credential from
portable to proxied-and-revocable, but it does not yet narrow *which* repos a
given key may reach.

Per-key → repo scoping (see "Deferred to v2") is the intended fix. Until then,
the interim guidance is to keep each relay's PAT set minimal, and to run a
**separate relay instance per trust domain** (its own host key, allowlist, and
store) rather than pooling unrelated repos behind one allowlist. This limitation
is acceptable for a first pass but should be closed before the relay fronts
repos of materially different sensitivity.

## Architecture

```
   UTM guest VM                       Mac host
┌──────────────┐   git over SSH   ┌───────────────────────────┐  git/HTTPS  ┌────────┐
│ agent (git)  │ ───────────────▶ │  patvault relay           │ ──────────▶ │ GitHub │
│ agent SSH    │  host-only net,  │   • SSH server            │  PAT        │        │
│ key only     │  fixed priv. IP  │   • pkt-line ↔ HTTPS bridge│  injected   │        │
│ (no PAT)     │                  │   • encrypted PAT store    │             │        │
│              │                  │   • macOS Keychain         │             │        │
└──────────────┘                  └───────────────────────────┘             └────────┘
```

### Considered and rejected: the local-mirror relay

A forge like Gitea serves git by exec'ing the real `git-upload-pack` /
`git-receive-pack` binaries against local repositories. That suggests an
alternative: instead of a live pkt-line↔HTTPS bridge, keep a **local mirror** of
each repo (synced to GitHub over HTTPS+PAT) and serve the agent from the mirror
by exec'ing real git — letting real git do all the protocol framing.

Rejected: staleness windows between syncs, disk cost per repo, push-race
complexity (agent push vs. background sync), and it breaks the "transparent,
always-current clone/fetch/push" goal. The live bridge is chosen deliberately.

### Agent-facing transport: SSH

Git speaks SSH natively and SSH provides mutual key authentication with no local
CA, which is why it is the agent-facing transport (versus an HTTPS forward-proxy
that would require MITM TLS with a CA the guest must trust, plus a weaker
agent-auth story).

Guest configuration:

```
# guest ~/.ssh/config
Host patvault
  HostName 192.168.64.1      # the host's IP on the host-only network
  Port 2222
  IdentityFile ~/.ssh/agent_ed25519

# remotes use the alias; the URL carries no secret
git remote add origin patvault:owner/repo
```

The relay is an SSH **server** (via `golang.org/x/crypto/ssh`, already a
dependency) that:

1. Presents a host key generated once at first run. The guest pins it in
   `known_hosts`, preventing impersonation on the private network.
2. Authenticates the client by public key against an allowlist (see
   "Authorized keys"). In v1 any authorized key may reach any repo that has a
   stored PAT.
3. Handles the `exec` request only — never a shell/pty (see "Exec parsing").

The structure of the SSH side (publickey auth, exec restriction to git commands)
mirrors what Gitea's built-in SSH server does; we build directly on
`x/crypto/ssh` rather than take a wrapper dependency, since the surface is small.

### Exec parsing

Git sends the transport command as a single `exec` string on the channel. A
single `parseExec(cmd string) (op, repo string, err error)` in
`internal/relay/exec.go` handles it, with these hazards addressed explicitly:

1. **Shell quoting.** Git sends `git-upload-pack 'owner/repo'` — the path is
   single-quoted (a path containing a space or apostrophe is shell-escaped). We
   strip one level of shell quoting rather than naive whitespace-splitting.
2. **Command allowlist.** Accept only `git-upload-pack` (read) and
   `git-receive-pack` (write), the hyphen form git-the-client always sends over
   SSH. **`git-upload-archive` is explicitly rejected** — it would expose
   `git archive --remote`, a capability we do not want to relay. Everything
   else is rejected.
3. **Path normalization.** Strip the surrounding quotes, then a leading `/` if
   present (`'/owner/repo'`), then feed through the existing
   `urlparse.NormalizePath` (which already strips a trailing `.git` and `/`), so
   `'owner/repo.git'`, `'/owner/repo'`, and `'owner/repo/'` all resolve to the
   stored `(github.com, owner/repo)` key.
4. **Shape check.** After normalizing, require exactly `owner/repo` (two
   non-empty segments, no `..`, no extra slashes) before the value is ever
   interpolated into an upstream URL — defense against path-traversal / SSRF-ish
   input.

Anything failing parse → the disallowed-exec error (exit 128; see "Errors").

Mapping:

- `git-upload-pack '<owner/repo>'`  → read  (clone/fetch)
- `git-receive-pack '<owner/repo>'` → write (push)

### Wire protocol: require v2 for fetch

Git's transports come in two flavors. **SSH is stateful** — one bidirectional
connection whose server remembers the negotiation across rounds. **HTTP is
stateless** ("stateless-rpc") — each request stands alone. For a *fetch*,
protocol **v0** negotiation is a genuine multi-round back-and-forth (`want` /
`have` / ack), which the stateful SSH server holds naturally but which our
stateless HTTP upstream does not. A naive byte-pump bridging a stateful v0 SSH
client to a stateless HTTP upstream **desyncs on any incremental fetch** (a
fetch where the agent already has history); only a fresh clone — one round, no
`have`s — would appear to work. Bridging v0 correctly would require the relay to
drive the negotiation itself (accumulate the client's `have`s and replay them on
each stateless POST) — a negotiation engine, not a bridge.

Protocol **v2** dissolves this: its `fetch` command is self-contained and
stateless *by design*, so the same request works identically over stateful and
stateless transports. Bridging a v2 SSH client to a v2 HTTP upstream is thin —
each `ls-refs` / `fetch` command maps to exactly one POST.

**Decision: v1 requires protocol v2 for fetches.** The client signals v2 by
sending `GIT_PROTOCOL=version=2` as an `env` request on the SSH channel before
the exec; the relay captures it and forwards it upstream as the `Git-Protocol`
header. If a `git-upload-pack` request arrives *without* `version=2`, the relay
fails fast (see "Errors"):

```
patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2' (default since git 2.26)
```

We control the guest, so this is a trivial constraint, and v2 is git's default
since 2.26.

Confirmed by the relay SSH spike against the local git/ssh binaries; see
`docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md`.

**Push is unaffected.** `git-receive-pack` has no v2; a push is always one
advertise-GET + one commands+packfile POST + a `report-status` reply, inherently
single-shot, and bridges cleanly regardless of the negotiated version.

### Relay → GitHub: the pkt-line ↔ HTTPS bridge

This is the one substantial new component (`internal/relay/bridge.go`). It is a
**server-side re-implementation of git's own `remote-curl`** — the client-side
code that bridges git's local pkt-line protocol to smart-HTTP — run in the
server direction, injecting the PAT upstream as HTTP Basic auth:
`Authorization: Basic base64("x-access-token:<PAT>")`.

**Basic, not Bearer.** GitHub's Git HTTP transport (`github.com/<owner>/<repo>.git`)
answers `Authorization: Bearer <PAT>` with 401, even for a valid fine-grained PAT
that the REST API accepts on the same token. Bearer works on `api.github.com`;
the Git endpoints do not honor it. The username in the Basic pair is ignored —
`x-access-token` is the conventional placeholder. Confirmed by the relay v2 spike
against real GitHub; see `docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md`.

The relay does **not** need to understand refs, packs, wants, or haves. It moves
framed pkt-lines between the SSH channel and HTTP bodies. It therefore needs
pkt-line *framing* only — length-prefix scanning to find flush-pkt (`0000`) /
delim-pkt (`0001`) boundaries — not go-git's object/ref machinery. We vendor or
copy a small `format/pktline`-style scanner rather than take a wholesale go-git
dependency (large tree, heavier server model than a relay needs, and immature
v2 support; the canonical v2 reference is git's `gitprotocol-v2.txt` /
`remote-curl.c`).

**Fetch (`git-upload-pack`, v2):**

1. **Advertisement.** `GET
   https://github.com/<owner>/<repo>.git/info/refs?service=git-upload-pack` with
   the PAT and `Git-Protocol: version=2`. The HTTP response prefixes a
   `# service=git-upload-pack` pkt-line + flush that the SSH transport does not
   use — strip it, forward the remaining capability advertisement to the client.
2. **Command pump (stateless-rpc).** Loop: read one client command from the SSH
   channel up to its terminating flush-pkt (v2 commands like `ls-refs` and
   `fetch` are self-contained), `POST .../git-upload-pack` with the PAT,
   `Git-Protocol: version=2`, `Content-Type: application/x-git-upload-pack-request`,
   and that body; stream the response back down the SSH channel. Repeat until
   the client sends no more (channel EOF).

Because the client's `fetch` command is forwarded verbatim, **partial clone
(`filter=blob:none`) and shallow clone (`depth`) work for free.**

**Push (`git-receive-pack`, single-shot):**

1. **Advertisement.** `GET .../info/refs?service=git-receive-pack` with the PAT;
   strip the `# service=` banner + flush; forward the ref advertisement.
2. **Update.** Relay the client's ref-update commands + packfile to
   `POST .../git-receive-pack` (PAT, `Content-Type:
   application/x-git-receive-pack-request`) and stream the `report-status` back.
   **The client's EOF terminates the body.** git sends commands + flush + a raw
   (un-framed) packfile and then half-closes its write side while still reading
   the response, so the bridge copies the channel into the POST body until EOF
   and never parses the pack — this is what keeps the push path a pump. It also
   means a delete-only push (which sends no pack at all) needs no special case.
   Confirmed by the push framing probe against a real git client; see
   `docs/superpowers/notes/2026-07-16-relay-push-framing-probe.md`. The body
   length is unknown up front, so the POST goes out chunked; that GitHub accepts
   a chunked receive-pack body is **not yet verified** (see §"Unverified
   assumptions").

**Cross-cutting bridge rules:**

- **Stream, never buffer**, in both directions — packfiles can be large.
- Set correct `Content-Type` on POSTs and `Accept:
  application/x-git-upload-pack-result` / `-receive-pack-result`.
- **Pass GitHub's sideband channels through untouched** — progress (2) and error
  (3) messages reach the client and git displays them as `remote:` natively.
- Repo resolution: the normalized `<owner/repo>` looks up the stored credential
  for `(github.com, owner/repo)`; if no non-expired credential exists, the relay
  refuses before contacting GitHub (see Expiry and Errors).

### Errors and exit codes

The governing principle is that once pkt-line streaming to the client begins it
cannot be cleanly interrupted, so:

- **Fail-before-first-byte invariant.** The relay completes *all* fallible
  validation — pubkey auth, exec parse, v2 check, repo resolution, expiry check,
  **and the upstream `info/refs` advertisement GET returning 2xx** — before it
  writes a single byte to the client's stdout channel. Only once the
  advertisement is confirmed good does streaming begin.
- **Error surface: stderr + `exit-status`, never stdout.** Errors are written as
  plain text to the SSH channel's stderr (extended-data), followed by a non-zero
  `exit-status` request before close. Injecting text into stdout would corrupt
  git's pkt-line parser. Over SSH, git passes remote stderr straight to the
  user's terminal, so a `patvault:`-prefixed line is displayed readably.
- **Mid-stream failures cannot be clean.** If the connection drops after
  streaming has started, the relay closes the channel with a non-zero
  `exit-status` and logs host-side; upstream errors GitHub itself reports via
  sideband channel 3 pass through and abort the client natively.

Messages are worded to tell the calling agent **whether retrying can help**, so
an agent does not loop on a terminal failure:

| Condition | stderr message | retry | exit |
|---|---|---|---|
| No/expired PAT for repo | `patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh — this will not succeed until then` | terminal | 1 |
| GitHub 401/403 | `patvault: github rejected the token for owner/repo (revoked or insufficient scope); refresh with 'patvault add' on the host — this will not succeed until then` | terminal | 1 |
| GitHub 404 | `patvault: owner/repo not found, or the stored token cannot see it` | terminal | 1 |
| GitHub 5xx / network | `patvault: github unreachable (503); safe to retry shortly` | retryable | 1 |
| Fetch without protocol v2 | `patvault: relay requires git wire protocol v2; run 'git config --global protocol.version 2'` | terminal | 1 |
| Disallowed exec (shell/pty/unknown/`upload-archive`) | `patvault: only git fetch/push are permitted` | terminal | 128 |

Exit codes are low-stakes (git treats any non-zero as failure); `1` is used for
credential/upstream refusals and `128` (git's fatal convention) for protocol
violations.

### Upstream credential: pre-provisioned, self-expiring PATs

The relay holds exactly what patvault stores today — single-repo fine-grained
PATs, encrypted at rest, master key in the Keychain. It selects the PAT matching
the requested repo and injects it. It never mints, renews, or calls GitHub's
token API.

The relay does **not** inspect the PAT's scope. If a read-only token is used for
a push, GitHub returns 403 and the error table reports it; GitHub is the
authority on read-vs-write, and introspecting a fine-grained token's permissions
would require an extra API call for no gain.

### Expiry as a feature

No background renewal exists by design. A dormant project's PAT simply lapses,
which matches how work actually pauses. When a request targets a repo whose
stored PAT is missing or expired, the relay refuses before contacting GitHub and
returns the terminal expired-token error above.

Refreshing is the existing `patvault add` flow on the host — the one place the
GitHub 2FA dance happens, when the operator chooses to resume the project.

## Runtime, config, and concurrency

- **Lifecycle.** `patvault relay serve` runs the SSH server in the foreground
  until SIGINT/SIGTERM, then shuts down gracefully (stop accepting, drain
  in-flight operations, close). How it is kept alive — launchd, tmux, a future
  GUI — is out of scope; it is a normal foreground server.
- **Listen address.** Explicit `--listen <ip:port>` required; no auto-detection
  of the host-only interface (auto-detect risks binding wider than intended for
  a security boundary). Omitting it is a startup error. Binds to the host-only
  interface IP only, never `0.0.0.0`.
- **Host key.** An ed25519 host key generated once on first `serve`, stored at
  `~/.config/patvault/relay_host_ed25519` (mode 0600) and reused across restarts
  so the guest's `known_hosts` pin stays valid. Its fingerprint is printed on
  generation so the operator can pin it. `--host-key <path>` overrides.
- **Authorized keys.** Standard OpenSSH `authorized_keys` format (one pubkey per
  line) at `~/.config/patvault/relay_authorized_keys`, parsed with
  `ssh.ParseAuthorizedKey`. `patvault relay add-key <pubkey>` appends and
  de-duplicates; operators may also hand-edit. `--authorized-keys <path>`
  overrides.
- **Concurrency.** Connections are handled concurrently (a goroutine per
  channel). There is no shared mutable state — SQLite reads are safe and the
  master key is fetched once per process and cached (matching the existing "one
  keychain lookup per process" design).
- **Operational logging.** A host-side structured log records each connection:
  timestamp, agent-key fingerprint, operation (fetch/push), repo, and outcome
  (ok / refused-expired / github-403 / …). It **never logs the PAT**. This is
  the *operational/debug* log, explicitly distinct from the stronger,
  tamper-resistant **v2 audit log**, which stays deferred.

## Deployment: macOS host + UTM guest

- **Networking:** use a UTM **Emulated VLAN / host-only network** so the host
  holds a stable private IP (e.g. `192.168.64.1`) and the link is not routable
  off the Mac. Shared (NAT) also works — the host is reachable at the gateway —
  but host-only exposes nothing externally and is preferred.
- **Host key pinning:** the relay generates its SSH host key once; the guest
  pins the printed fingerprint in `known_hosts`.
- **Keychain:** the first Keychain access may surface an unlock/allow prompt,
  exactly as any other `patvault` command does today (the relay reuses the
  existing keyring code) — not a bug.

## Command surface

```
patvault relay serve   [--listen <ip:port>] [--authorized-keys <path>] [--host-key <path>]
patvault relay add-key <path-to-pubkey>     # append to the allowlist (dedup)
```

`patvault add` / `list` / `remove` on the host manage the PAT store exactly as
today. `patvault credential …` remains for non-relay use.

## Module layout

| Path | Responsibility |
|------|----------------|
| `internal/relay/server.go` | SSH server: listener, host key, publickey auth against allowlist, `env` (GIT_PROTOCOL) capture, exec-request dispatch, graceful shutdown |
| `internal/relay/exec.go` | `parseExec`: shell-unquote, command allowlist (reject `upload-archive`), normalize + `owner/repo` shape check |
| `internal/relay/bridge.go` | v2 stateless-rpc pump + single-shot push bridge; pkt-line framing scanner; `# service=` strip; PAT injection; streamed copy; sideband pass-through |
| `internal/relay/authkeys.go` | Load/append the OpenSSH-format allowlist |
| `internal/relay/pktline.go` | Minimal pkt-line length-prefix scanner (flush/delim boundary detection) |
| `internal/commands/relay.go` | `patvault relay serve` / `add-key` cobra wiring |
| `internal/encrypt`, `internal/db`, `internal/urlparse` | **reused unchanged** — store, decrypt, and normalize |

Dependency injection matches the existing style: the SSH server takes the DB
`open` func and the `encrypt.Keyring`; the bridge takes an `http.Client` (fakable
in tests).

## Sequence: `git push` through the relay

```
agent git            relay (host)                         GitHub
   │ ssh exec         │                                     │
   │ git-receive-pack ├─ authenticate pubkey (allowlist)    │
   │  'owner/repo' ──▶ ├─ resolve owner/repo → stored PAT    │
   │                  ├─ (expired? → stderr error, close)    │
   │                  ├─ GET info/refs?service=…receive-pack │
   │                  │        Authorization: Basic PAT ────▶│
   │                  ├─ (non-2xx? → stderr error, close)     │
   │ ◀── ref adv ─────┤◀──────────── ref advertisement ──────│
   │ ── cmds+pack ───▶├─ POST /git-receive-pack (PAT) ──────▶│
   │ ◀ report-status ─┤◀───────────── report-status ─────────│
   │ close (exit 0)   │                                     │
```

The PAT appears only on the middle leg. The agent side carries only git data
authenticated by the agent's SSH key. Note the fail-before-first-byte checks
(expiry, non-2xx advertisement) precede any byte sent to the client.

## Testing

- **exec parsing:** valid `git-upload-pack`/`git-receive-pack` + repo extraction
  through shell quoting and `.git`/slash normalization; rejection of shells,
  ptys, `git-upload-archive`, and unknown commands; `owner/repo` shape rejection
  of traversal input.
- **protocol v2 gate:** a `git-upload-pack` request without
  `GIT_PROTOCOL=version=2` is refused with the enable-v2 message before any
  upstream call.
- **authz (v1):** a request for a repo with no stored (or expired) PAT is refused
  before any upstream call (inject an `http.Client` that fails the test if
  called).
- **bridge:** against a stub HTTPS smart-protocol server, assert the
  `# service=` advertisement prefix is stripped, the PAT and `Git-Protocol`
  header are injected on `info/refs` and every command POST, the correct
  `Content-Type` is set, bodies stream rather than buffer, and bytes round-trip
  for a v2 fetch (ls-refs + fetch) and a push.
- **fail-before-first-byte:** a non-2xx advertisement GET produces a stderr
  message + non-zero exit and *no* bytes on the client stdout channel.
- **error table:** each condition maps to the specified message, retry-wording,
  and exit code.
- **auth / host key:** publickey accepted only when present in the allowlist;
  host key stable across restarts (fingerprint unchanged).
- **end-to-end (highest investment):** drive *real* `git clone` / incremental
  `git fetch` / `git push` against the relay wired to a stub upstream, since
  that is the only way to be sure the pkt-line framing and v2 command boundaries
  are byte-correct. A manual integration variant runs against real GitHub.
- **reuse:** store/decrypt paths exercised through the existing `internal/db` /
  `internal/encrypt` tests; no new crypto.

## Unverified assumptions (follow-ups before/during implementation)

These are claims this spec makes that no live evidence supports yet. They are
not deferred *features* — they are things believed true and never checked. The
relay v2 spike (`docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md`)
validated the v2 fetch protocol assumptions but falsified this spec's auth
scheme, so "stated confidently, never tested" is a known failure mode here.

- ~~**Push against real GitHub is untested.**~~ **SETTLED (2026-07-16)** — see
  `docs/superpowers/notes/2026-07-16-relay-push-spike-findings.md`. A real push
  to a private repo confirmed the `git-receive-pack` advertisement framing
  (same `# service=` banner + flush as upload-pack), the auth scheme (Basic
  **200**, Bearer 401, unauth 401 — the v2 note's Basic-not-Bearer correction
  carries over), and the commands+packfile POST / `report-status` round-trip
  (`unpack ok` / `ok <ref>`). "Push is unaffected by the version gate" also
  held: receive-pack ignored a `Git-Protocol: version=2` header and answered a
  classic ref-list. Two caveats survive into implementation: **a delete-only
  push sends no pack at all**, so the bridge must not assume pack bytes follow
  the commands; and the `report-status` **rejection (`ng`) path is still
  unobserved** — every command in that run succeeded.
- ~~**The pack body has never been streamed end to end.**~~ **SETTLED
  (2026-07-18)** — closed by slices 3–4's stub-upstream and end-to-end gates and
  the slice-5 real-GitHub run (see
  `docs/superpowers/notes/2026-07-18-relay-slice-5-real-github-findings.md`). Real
  `git clone` / incremental `git fetch` / `git push` through the relay stream real
  packfiles with sideband report-status forwarded verbatim; the bridge never
  buffers a pack (except a delete-only push, which has no pack). The bridge does
  not interpret sections, so fetch section order remains a non-dependency.
- ~~**GitHub accepting a chunked receive-pack request body is unverified.**~~
  **SETTLED (2026-07-18)** — same note. A real `git push` through the relay was
  accepted with a `Transfer-Encoding: chunked` body; the `remote-curl` expectation
  held, and `pushPack` streams chunked unchanged. (A delete-only push is the one
  case that does not go out chunked: it carries no pack, git does not half-close,
  so the relay sends the buffered command list with a known `Content-Length` — see
  the findings note and `internal/relay/bridge.go`.)
- ~~**The status→message mapping in §Errors is inferred, not observed.**~~
  **SETTLED (2026-07-18)** — same note. Observed on the Git endpoints: accessible
  repo **200**, unauthenticated private repo **401**, nonexistent repo **404**.
  `classifyStatus`'s rows match as-is (401/403 → auth, 404 → not-found, 5xx →
  unreachable). The no-access-repo and revoked-vs-expired distinctions were not
  separately reproduced (one repo + one token); both map to the same message and
  action, and an expired PAT never reaches GitHub (the relay refuses it locally).

## Deferred to v2

- Per-key → repo/permission authorization (an agent key scoped to a subset of
  repos, and read-vs-write asymmetry). **This closes the flat-authorization
  limitation called out in the threat model** — the highest-priority
  improvement, since v1 grants every authorized key access to every stored PAT.
- Policy enforcement: approval-required pushes, force-push and ref-deletion
  denial, protected branches. (This is the space FINOS git-proxy occupies.)
- Tamper-resistant audit log of every fetch/push per agent key (distinct from
  the v1 operational log).
- Rate limiting per agent key.
- A front-end (menu-bar / GUI) wrapping the headless relay engine for explicit
  lifecycle and one-click token refresh.
