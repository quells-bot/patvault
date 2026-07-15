# Patvault: Credential-Injecting Relay

Status: proposed
Date: 2026-07-15
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

The relay is an SSH **server** (via `golang.org/x/crypto/ssh`) that:

1. Presents a host key generated once at first run. The guest pins it in
   `known_hosts`, preventing impersonation on the private network.
2. Authenticates the client by public key against an allowlist (`authorized
   keys`). In v1 any authorized key may reach any repo that has a stored PAT.
3. Handles the `exec` request only — never a shell/pty. It parses the git
   transport command:
   - `git-upload-pack '<owner/repo>'`  → read  (clone/fetch)
   - `git-receive-pack '<owner/repo>'` → write (push)
   Any other exec request is rejected.

### Relay → GitHub: the pkt-line ↔ HTTPS bridge

This is the one substantial new component. Over SSH, git speaks the stateful
pkt-line protocol on the channel's stdin/stdout. Over HTTPS, GitHub speaks the
stateless smart protocol as request/response pairs. The relay re-originates the
exchange upstream, injecting `Authorization: Bearer <PAT>`, and translates
between the two framings. The streams are nearly identical; the differences are
mechanical:

For a fetch (`git-upload-pack`):

1. **Ref advertisement.** `GET https://github.com/<owner>/<repo>.git/info/refs?service=git-upload-pack`
   with the PAT. The HTTP response prefixes a `# service=git-upload-pack`
   pkt-line + flush that the SSH transport does not use — strip it, forward the
   remaining advertisement to the client.
2. **Negotiation + pack.** Read the client's `want`/`have` pkt-lines up to its
   flush/`done`, `POST .../git-upload-pack` with the PAT and that body, then
   stream the packfile response back down the SSH channel.

For a push (`git-receive-pack`), the same shape in reverse: advertise refs via
`info/refs?service=git-receive-pack`, then relay the client's update commands +
packfile to `POST .../git-receive-pack` and stream the report-status back.

Repo resolution: the `<owner/repo>` from the exec request is normalized
(`internal/urlparse.NormalizePath`) and used to look up the stored credential
for `(github.com, owner/repo)`. If no non-expired credential exists, the relay
refuses before contacting GitHub (see Expiry).

### Upstream credential: pre-provisioned, self-expiring PATs

The relay holds exactly what patvault stores today — single-repo fine-grained
PATs, encrypted at rest, master key in the Keychain. It selects the PAT matching
the requested repo and injects it. It never mints, renews, or calls GitHub's
token API.

### Expiry as a feature

No background renewal exists by design. A dormant project's PAT simply lapses,
which matches how work actually pauses. When a request targets a repo whose
stored PAT is missing or expired, the relay:

- refuses the operation before contacting GitHub, and
- returns a human-readable error down the SSH channel's stderr, e.g.
  `patvault: token for github.com/owner/repo expired 2026-07-01; run 'patvault add' on the host to refresh`.

Refreshing is the existing `patvault add` flow on the host — the one place the
GitHub 2FA dance happens, when the operator chooses to resume the project.

## Deployment: macOS host + UTM guest

- **Networking:** use a UTM **Emulated VLAN / host-only network** so the host
  holds a stable private IP (e.g. `192.168.64.1`) and the link is not routable
  off the Mac. Shared (NAT) also works — the host is reachable at the gateway —
  but host-only exposes nothing externally and is preferred.
- **Bind narrowly:** the relay's SSH listener binds to the host-only interface
  IP only, never `0.0.0.0`. It is unreachable from anything but the guest.
- **Host key pinning:** the relay generates its SSH host key once; the guest
  pins it in `known_hosts`.
- **Lifecycle:** the relay runs as a launchd user agent on the host.

## Command surface (proposed)

```
patvault relay serve   [--listen <ip:port>] [--authorized-keys <path>] [--host-key <path>]
patvault relay add-key <path-to-pubkey>     # append to the allowlist
```

`patvault add` / `list` / `remove` on the host manage the PAT store exactly as
today. `patvault credential …` remains for non-relay use.

## Module layout (proposed)

| Path | Responsibility |
|------|----------------|
| `internal/relay/server.go` | SSH server: listener, host key, publickey auth against allowlist, exec-request dispatch |
| `internal/relay/exec.go` | Parse `git-upload-pack` / `git-receive-pack` + repo path; reject anything else |
| `internal/relay/bridge.go` | pkt-line ↔ HTTPS smart-protocol translation, PAT injection, stream copy |
| `internal/relay/authkeys.go` | Load/append the SSH public-key allowlist |
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
   │                  │        Authorization: Bearer PAT ───▶│
   │ ◀── ref adv ─────┤◀──────────── ref advertisement ──────│
   │ ── cmds+pack ───▶├─ POST /git-receive-pack (PAT) ──────▶│
   │ ◀ report-status ─┤◀───────────── report-status ─────────│
   │ close            │                                     │
```

The PAT appears only on the middle leg. The agent side carries only git data
authenticated by the agent's SSH key.

## Testing

- **exec parsing:** valid `git-upload-pack`/`git-receive-pack` + repo extraction;
  rejection of shells, ptys, and unknown commands.
- **authz (v1):** a request for a repo with no stored (or expired) PAT is refused
  before any upstream call (inject an `http.Client` that fails the test if
  called).
- **bridge:** against a stub HTTPS smart-protocol server, assert the
  `# service=` advertisement prefix is stripped for the SSH side, the PAT is
  injected on both `info/refs` and the pack POST, and bytes round-trip for a
  fetch and a push.
- **auth:** publickey accepted only when present in the allowlist; host key
  stable across restarts.
- **reuse:** store/decrypt paths exercised through the existing `internal/db` /
  `internal/encrypt` tests; no new crypto.

## Deferred to v2

- Per-key → repo/permission authorization (an agent key scoped to a subset of
  repos, and read-vs-write asymmetry).
- Policy enforcement: approval-required pushes, force-push and ref-deletion
  denial, protected branches.
- Audit log of every fetch/push per agent key.
- Rate limiting per agent key.

## Open questions

- Should the relay expose read-only (`upload-pack`) even when only a write PAT is
  stored, or require the stored token's scope to match the operation? (Leaning:
  v1 doesn't inspect scope; GitHub enforces it upstream.)
- Should `patvault relay serve` auto-detect the host-only interface IP, or
  require an explicit `--listen`? (Leaning: explicit, to avoid binding wider than
  intended.)
