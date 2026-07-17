# relay-ssh spike (throwaway)

Verifies what patvault's relay will actually receive from a real `git` client
over SSH, before any relay/SSH code exists. Not part of the shipped binary.

## Run

    go run ./spike/relay-ssh

No credentials, no network, no GitHub: it binds `127.0.0.1:0` and drives the
local `git` binary at itself. Requires `git` and OpenSSH `ssh` on PATH.

## What it checks

1. A real `git` fetch (`ls-remote`, `protocol.version=2`) sends
   `GIT_PROTOCOL=version=2` as an SSH `env` request **before** the `exec`
   request — the assumption the relay's "require v2 for fetch" decision rests on
   (`docs/superpowers/specs/2026-07-15-relay-design.md`, §"Wire protocol").
2. Under `protocol.version=0`, git does **not** announce `version=2`, so the v2
   gate can tell the two apart and fail closed.
3. Under `protocol.version=1`, git **does** send `GIT_PROTOCOL` — carrying
   `version=1`. The v2 gate must therefore compare the env request's *value*; a
   gate keyed on the request's presence admits a v1 client as v2 and fails open.
4. A real `git push` sends a `git-receive-pack` exec, and the exact exec string
   is recorded for `internal/relay/exec.go`'s parser.

The server accepts any public key and refuses every exec with exit-status 1, so
git always reports failure. That is expected: the captured requests are the
result, not git's exit code.
