# Patvault: Hardening the `list` Command

Status: proposed
Date: 2026-07-15
Supersedes: the `--show` behavior described in the original patvault design.

## Overview

This spec redesigns `patvault list` to remove its ability to emit plaintext
tokens and to give humans a *useful* way to identify credentials without ever
revealing the secret.

The motivating observation: **a full PAT shown to a human is worthless.** GitHub
displays a PAT exactly once, at generation time. The operator keeps no local
copy to compare against, so `patvault list --show` cannot help them verify "is
this the token I think it is." The only thing full-token output reliably does is
hand the cleartext secret to whatever is reading stdout — a log file, a captured
subprocess, or a coding agent running as the same user. `--show` is therefore
pure downside: no legitimate human benefit, a clean exfiltration path.

At the same time, `list` currently holds a capability it does not need: it
takes an `encrypt.Keyring`, fetches the master key, and **decrypts every stored
token on every invocation** (to mask or reveal it). A command whose job is to
enumerate metadata should not have a code path that touches plaintext at all.

## Goals

- Remove `--show`; `list` never emits a plaintext token.
- Give operators a **fingerprint** — a short, non-reversible identifier — so
  they can still answer real questions: "does patvault already hold *this*
  token?", "did I reuse one token across repos?", "which entry is stale?".
- Remove the master key and decryption from the `list` code path entirely, so
  the command *structurally cannot* leak a token (defense by capability
  removal, not by policy).
- Preserve existing useful signals: host, path, username, token type, expiry,
  and `--prune`.

## Non-goals

- Gating `patvault credential get`. That path must remain silent and ungated —
  git depends on it. An agent that can run `git credential fill` can still
  obtain the token; closing that is a separate, larger design (a broker/proxy
  that keeps the secret outside the caller's trust boundary). This spec only
  removes the *gratuitous* egress that `list --show` represents.
- Changing the encryption or key-derivation scheme for stored tokens.

## The fingerprint

A fingerprint lets a human or script compare a token they hold in hand (freshly
copied from GitHub, or sitting in a password manager) against what patvault has
stored, without either side revealing the secret.

Definition:

```
fingerprint = HMAC-SHA256(masterKey, "patvault-fingerprint-v1" || tokenPlaintext)
display     = base32-lower(fingerprint)[:8]      // e.g. "a1b2c3d4"
```

Properties and rationale:

- **Non-reversible.** HMAC-SHA256 is preimage-resistant. PATs are high-entropy
  (>150 bits), so even with the DB and fingerprints in hand an attacker cannot
  brute-force the token from the fingerprint.
- **Keyed by the master key**, with a domain-separation label distinct from the
  AES key's `info`. This means fingerprints are stable *per token across repos*
  (same secret → same fingerprint everywhere), which surfaces token reuse, and
  are not comparable across users/machines (no global GitHub-token rainbow
  table).
- **Stored, not recomputed.** The fingerprint is written to a new `fingerprint`
  column at add/store time — the one place plaintext already exists. `list`
  reads the column directly and never decrypts.
- **8 chars / 40 bits displayed** — enough to disambiguate a personal set of
  credentials with negligible collision risk, short enough to eyeball.

A companion helper, `patvault fingerprint` (reads a token on stdin, prints its
fingerprint under the current master key), lets an operator check a token they
hold against the `list` output:

```
$ printf '%s' "$COPIED_TOKEN" | patvault fingerprint
a1b2c3d4
$ patvault list        # find a1b2c3d4 in the Fingerprint column → it's stored
```

This gives back the *only* legitimate capability `--show` ever provided
(confirming identity) while revealing nothing.

## Command surface changes

`internal/commands/list.go`:

- **Remove** the `--show` flag and `maskPAT`-based reveal branch.
- **Drop** the `kr encrypt.Keyring` parameter from `NewListCmd` / `runList`.
  Signature becomes `runList(d *db.DB, out io.Writer, prune bool)`. `main.go`'s
  `buildListCmd` stops calling `selectKeyring()`.
- Keep `--prune` unchanged.
- Token **type** (fine-grained vs classic) is still shown — it is useful for
  spotting a non–fine-grained token — but is now read from a stored `token_type`
  column rather than recovered by decrypting and prefix-matching. See migration.

New default output:

```
Host        Path                  Username    Type        Fingerprint  Expires
github.com  quells-bot/patvault   quells-bot  github_pat  a1b2c3d4     ⚠ 5 days
github.com  another-org/some-repo quells-bot  github_pat  a1b2c3d4     89 days
github.com  old-org/legacy        quells-bot  ghp         9f8e7d6c     (expired)
```

(The repeated `a1b2c3d4` immediately shows one token reused across two repos —
a signal the old masked/`--show` output could not give.)

`maskPAT` and `patPrefixes` move out of the display path. The prefix→type
mapping is reused at write time to populate `token_type`.

## Schema migration

Add two nullable columns:

```sql
ALTER TABLE credentials ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN token_type  TEXT NOT NULL DEFAULT '';
```

Populated on every write path (`runAdd`, `RunStore`) alongside the encrypted
blob, since plaintext is already in hand there.

Backfill for pre-existing rows:

- `list` shows `(legacy)` in the Fingerprint/Type columns for rows with an
  empty fingerprint — it must **not** decrypt to compute one, or it regains the
  capability we just removed.
- Rows are upgraded lazily and for free: the next `credential get` /
  `credential store` / `add` for that entry has the plaintext and writes the
  fingerprint. (`RunGet` can opportunistically backfill on a successful decrypt.)
- An explicit, clearly-labeled opt-in — `patvault list --refresh-fingerprints`
  — may decrypt all rows once to backfill. This is the single command that
  reintroduces decryption to `list`, so it is a separate flag, prints a warning,
  and exists only for migration convenience.

## Security analysis

What this closes:

- Eliminates the ungated plaintext-egress command. "Run `patvault list --show`
  and paste the output" no longer yields tokens.
- `list` loses the master-key capability: even a bug (format-string, logging,
  panic dump) in the list path cannot expose a token, because plaintext never
  enters it.

Residual risks (explicitly out of scope, worth restating):

- `patvault credential get` and `git credential fill` still return cleartext on
  demand. This design does not change that; an active agent retains that path.
- The fingerprint reveals token **reuse** and **type**. This is intended
  (reuse is a real signal to the operator) and is not sensitive.
- Fingerprint truncation (40 bits) allows deliberate collisions in the abstract,
  but the fingerprint is an identity aid for a human's own small credential set,
  never an authorization decision, so collision resistance is not security-load-
  bearing.

## Compatibility / behavior changes

- `--show` is removed. Any script relying on it breaks by design; the intended
  replacement is `patvault fingerprint` for identity checks. This is a
  deliberate, documented breaking change.
- Output gains `Type` and `Fingerprint` columns and drops the `PAT` column.
- README's `list` section and the sample output table are updated; the
  `--show` row in the options table is removed.

## Testing

- `runList` no longer needs a keyring fake; tests assert columns render from
  stored metadata with no decryption call (inject a DB whose keyring access
  would fail, to prove `list` never touches it).
- Fingerprint determinism: same token + same master key → same fingerprint;
  different master key → different fingerprint.
- `(legacy)` rendering for rows without a stored fingerprint.
- `--refresh-fingerprints` backfills and is the only list path that decrypts.
- `patvault fingerprint` reads stdin (hidden if TTY, plain otherwise, mirroring
  `readPassword`) and matches the value shown by `list` for the same token.

## Open questions

- Should `token_type` distinguish fine-grained vs classic more loudly (e.g. a
  `⚠ classic` marker), given fine-grained is the only design target?
- Should `patvault fingerprint` accept `--repo` to also confirm the token is
  stored for a specific `(host, path)` in one step?
