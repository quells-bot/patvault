# Relay SSH `GIT_PROTOCOL` Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, against a real `git` client, that git sends `GIT_PROTOCOL=version=2` as an SSH `env` request *before* the `exec` request — the assumption the relay's "require v2 for fetch" decision rests on — and capture the exact `exec` command strings git sends for fetch and push.

**Architecture:** A throwaway standalone Go program (`package main` under `spike/relay-ssh/`) that stands up a minimal in-process SSH server on `127.0.0.1:0` using `golang.org/x/crypto/ssh`, then drives the **real `git` binary** at it as a subprocess. The server accepts any public key, records every channel request in arrival order, and refuses the operation immediately after the `exec` (exit-status 1) — git fails, which is expected and irrelevant; the captured requests are the evidence. Deterministic parts (SSH request payload decoding, ordering logic) get real unit tests; the scenarios hard-assert and exit non-zero on failure, so running the program is itself the pass/fail gate.

**Tech Stack:** Go 1.26.5, `golang.org/x/crypto/ssh` (already a direct dependency — no new modules), the system `git` and OpenSSH `ssh` binaries.

## Global Constraints

- Go 1.26.5; module `github.com/quells-bot/patvault`.
- **No new module dependencies.** `golang.org/x/crypto` is already a direct require in `go.mod`; use its `ssh` package. Do not add an SSH server library.
- **Throwaway spike.** Lives under `spike/relay-ssh/`, `package main`, never imported by the shipped binary. Mirrors the existing `spike/relay-v2/` precedent.
- **No credentials, no network.** Everything binds `127.0.0.1` and talks to a local process. Never contacts GitHub. Nothing in this spike needs a PAT.
- **No secrets or absolute machine paths committed.** All keys are ephemeral, generated per run into `t.TempDir()` / `os.MkdirTemp`.
- `gofmt -w` all files before each commit; `go vet ./spike/relay-ssh/` must be clean.
- Assertion style follows `spike/relay-v2/main.go`: `pass(name)` prints `PASS: <name>`, `fail(name, format, ...)` prints `FAIL: ...` and calls `os.Exit(1)`.

## Why this spike exists

`docs/superpowers/specs/2026-07-15-relay-design.md` lines 254–257 state:

> The client signals v2 by sending `GIT_PROTOCOL=version=2` as an `env` request on the SSH channel before the exec; the relay captures it and forwards it upstream as the `Git-Protocol` header.

Everything downstream depends on it. The "require v2" decision (spec §"Wire protocol") is what lets the bridge be a thin pump instead of the negotiation engine the spec explicitly rejects (lines 245–247). If git does not send that env request where the relay can see it, the v2 gate refuses every fetch and the architecture section needs rewriting — so this is checked *before* the relay plan is written.

The mechanism being tested is not just git's behavior but OpenSSH's: git sets `GIT_PROTOCOL` in the ssh subprocess's environment, and the ssh client only forwards env vars it is told to send. Git adds `-o SendEnv=GIT_PROTOCOL` itself, but only when it recognizes the ssh command as an OpenSSH variant. That detection is part of what's under test, which is why the scenarios drive the real `ssh` binary through `GIT_SSH_COMMAND` rather than an in-process client.

The sibling spike `spike/relay-v2/` validated the *upstream* half (HTTP v2 round-trips) and falsified this spec's auth scheme; see `docs/superpowers/notes/2026-07-16-relay-v2-spike-findings.md`. This spike covers the *agent-facing* half.

## File Structure

| File | Responsibility |
|---|---|
| `spike/relay-ssh/sshreq.go` | SSH channel-request payload types and decoders (`env`, `exec`, `exit-status`). The deterministic, unit-tested core. |
| `spike/relay-ssh/sshreq_test.go` | Offline round-trip and malformed-payload tests for the decoders. |
| `spike/relay-ssh/server.go` | Ephemeral host key + `serveOnce()`: accepts one SSH connection, records requests in order, refuses after `exec`. Plus the `capture` type and its ordering predicates. |
| `spike/relay-ssh/server_test.go` | Offline test of `serveOnce()` driven by an in-process `x/crypto/ssh` client — no `git` binary needed. |
| `spike/relay-ssh/main.go` | Ephemeral client key, `GIT_SSH_COMMAND` wiring, and the three scenarios that drive the real `git` binary and assert. |
| `spike/relay-ssh/README.md` | How to run it and what it checks. |

---

### Task 1: SSH request payload decoding

The `env` and `exec` channel requests carry SSH-wire-encoded payloads (RFC 4254 §6.4, §6.5). `ssh.Unmarshal` decodes them into structs whose field order matches the wire format. This task isolates that so the rest of the spike deals in Go values.

**Files:**
- Create: `spike/relay-ssh/sshreq.go`
- Test: `spike/relay-ssh/sshreq_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `type envRequest struct { Name, Value string }`
  - `type execRequest struct { Command string }`
  - `type exitStatus struct { Status uint32 }`
  - `func parseEnvReq(payload []byte) (envRequest, error)`
  - `func parseExecReq(payload []byte) (execRequest, error)`

Note: these are named `parseEnvReq` / `parseExecReq`, **not** `parseExec`. The spec reserves `parseExec(cmd string) (op, repo string, err error)` for `internal/relay/exec.go`, which parses the command *string*; these decode the SSH *payload*. Keeping the names distinct avoids a false echo between the spike and the production package.

- [ ] **Step 1: Write the failing test**

Create `spike/relay-ssh/sshreq_test.go`:

```go
package main

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseEnvReq(t *testing.T) {
	payload := ssh.Marshal(envRequest{Name: "GIT_PROTOCOL", Value: "version=2"})

	got, err := parseEnvReq(payload)
	if err != nil {
		t.Fatalf("parseEnvReq: %v", err)
	}
	if got.Name != "GIT_PROTOCOL" {
		t.Errorf("Name = %q, want %q", got.Name, "GIT_PROTOCOL")
	}
	if got.Value != "version=2" {
		t.Errorf("Value = %q, want %q", got.Value, "version=2")
	}
}

func TestParseEnvReqRejectsTruncated(t *testing.T) {
	payload := ssh.Marshal(envRequest{Name: "GIT_PROTOCOL", Value: "version=2"})

	if _, err := parseEnvReq(payload[:6]); err == nil {
		t.Fatal("parseEnvReq(truncated) = nil error, want error")
	}
}

func TestParseExecReq(t *testing.T) {
	payload := ssh.Marshal(execRequest{Command: "git-upload-pack 'owner/repo'"})

	got, err := parseExecReq(payload)
	if err != nil {
		t.Fatalf("parseExecReq: %v", err)
	}
	if got.Command != "git-upload-pack 'owner/repo'" {
		t.Errorf("Command = %q, want %q", got.Command, "git-upload-pack 'owner/repo'")
	}
}

func TestParseExecReqRejectsTruncated(t *testing.T) {
	payload := ssh.Marshal(execRequest{Command: "git-upload-pack 'owner/repo'"})

	if _, err := parseExecReq(payload[:2]); err == nil {
		t.Fatal("parseExecReq(truncated) = nil error, want error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./spike/relay-ssh/`
Expected: FAIL — build error, `undefined: envRequest`, `undefined: parseEnvReq`, `undefined: execRequest`, `undefined: parseExecReq`.

- [ ] **Step 3: Write minimal implementation**

Create `spike/relay-ssh/sshreq.go`:

```go
package main

import "golang.org/x/crypto/ssh"

// envRequest is the payload of an SSH "env" channel request (RFC 4254 6.4).
// Field order matches the wire encoding.
type envRequest struct {
	Name  string
	Value string
}

// execRequest is the payload of an SSH "exec" channel request (RFC 4254 6.5).
type execRequest struct {
	Command string
}

// exitStatus is the payload of an "exit-status" channel request.
type exitStatus struct {
	Status uint32
}

func parseEnvReq(payload []byte) (envRequest, error) {
	var e envRequest
	if err := ssh.Unmarshal(payload, &e); err != nil {
		return envRequest{}, err
	}
	return e, nil
}

func parseExecReq(payload []byte) (execRequest, error) {
	var e execRequest
	if err := ssh.Unmarshal(payload, &e); err != nil {
		return execRequest{}, err
	}
	return e, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./spike/relay-ssh/ -v`
Expected: PASS — all four tests.

- [ ] **Step 5: Commit**

```bash
gofmt -w spike/relay-ssh/
git add spike/relay-ssh/sshreq.go spike/relay-ssh/sshreq_test.go
git commit -m "spike: ssh channel-request payload decoding for relay-ssh"
```

---

### Task 2: Capture server

A single-connection SSH server that records what a session asks for, in order, then refuses. It must answer the question "did GIT_PROTOCOL arrive *before* the exec?", so arrival order is recorded explicitly rather than inferred.

**Files:**
- Create: `spike/relay-ssh/server.go`
- Test: `spike/relay-ssh/server_test.go`

**Interfaces:**
- Consumes: `envRequest`, `execRequest`, `exitStatus`, `parseEnvReq`, `parseExecReq` (Task 1).
- Produces:
  - `type capture struct { Order []string; Envs []envRequest; Exec string; ExecSeen bool; Err error }`
  - `func (c *capture) gitProtocol() (string, bool)`
  - `func (c *capture) gitProtocolBeforeExec() bool`
  - `func newHostKey() (ssh.Signer, error)`
  - `func serveOnce(ln net.Listener, hostKey ssh.Signer) *capture`

- [ ] **Step 1: Write the failing test**

Create `spike/relay-ssh/server_test.go`. This drives `serveOnce` with an in-process ssh client — fast, hermetic, and no `git` binary involved:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialCapture starts serveOnce on a loopback listener, runs fn against it with
// an in-process ssh client, and returns what the server captured.
func dialCapture(t *testing.T, fn func(*testing.T, *ssh.Session)) *capture {
	t.Helper()

	hostKey, err := newHostKey()
	if err != nil {
		t.Fatalf("newHostKey: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan *capture, 1)
	go func() { done <- serveOnce(ln, hostKey) }()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	cc, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	sess, err := cc.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	fn(t, sess)
	sess.Close()

	select {
	case c := <-done:
		return c
	case <-time.After(20 * time.Second):
		t.Fatal("serveOnce did not return")
		return nil
	}
}

func TestServeOnceCapturesEnvThenExec(t *testing.T) {
	c := dialCapture(t, func(t *testing.T, sess *ssh.Session) {
		if err := sess.Setenv("GIT_PROTOCOL", "version=2"); err != nil {
			t.Fatalf("Setenv: %v", err)
		}
		// The server refuses with exit-status 1, so Run returns an ExitError.
		// That is expected; the capture is what matters.
		_ = sess.Run("git-upload-pack 'owner/repo'")
	})

	if c.Err != nil {
		t.Fatalf("capture error: %v", c.Err)
	}
	if !c.ExecSeen {
		t.Fatal("ExecSeen = false, want true")
	}
	if c.Exec != "git-upload-pack 'owner/repo'" {
		t.Errorf("Exec = %q, want %q", c.Exec, "git-upload-pack 'owner/repo'")
	}
	v, ok := c.gitProtocol()
	if !ok {
		t.Fatal("gitProtocol() not found, want version=2")
	}
	if v != "version=2" {
		t.Errorf("gitProtocol() = %q, want %q", v, "version=2")
	}
	if !c.gitProtocolBeforeExec() {
		t.Errorf("gitProtocolBeforeExec() = false, want true (Order = %v)", c.Order)
	}
}

func TestServeOnceExecWithoutEnv(t *testing.T) {
	c := dialCapture(t, func(t *testing.T, sess *ssh.Session) {
		_ = sess.Run("git-upload-pack 'owner/repo'")
	})

	if c.Err != nil {
		t.Fatalf("capture error: %v", c.Err)
	}
	if !c.ExecSeen {
		t.Fatal("ExecSeen = false, want true")
	}
	if _, ok := c.gitProtocol(); ok {
		t.Error("gitProtocol() found, want absent")
	}
	if c.gitProtocolBeforeExec() {
		t.Error("gitProtocolBeforeExec() = true, want false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./spike/relay-ssh/ -run TestServeOnce -v`
Expected: FAIL — build error, `undefined: newHostKey`, `undefined: serveOnce`, `undefined: capture`.

- [ ] **Step 3: Write minimal implementation**

Create `spike/relay-ssh/server.go`:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// sessionTimeout bounds a single captured session so a wedged client cannot
// hang the spike.
const sessionTimeout = 20 * time.Second

// capture records what one SSH session asked for, in arrival order.
type capture struct {
	Order    []string // request types as they arrived, e.g. ["env", "exec"]
	Envs     []envRequest
	Exec     string
	ExecSeen bool
	Err      error
}

// gitProtocol returns the value of the GIT_PROTOCOL env request and whether one
// was sent at all.
func (c *capture) gitProtocol() (string, bool) {
	for _, e := range c.Envs {
		if e.Name == "GIT_PROTOCOL" {
			return e.Value, true
		}
	}
	return "", false
}

// gitProtocolBeforeExec reports whether a GIT_PROTOCOL env request arrived
// before the first exec request. This is the ordering the relay depends on: it
// must know the protocol version at the moment it handles the exec, not after.
func (c *capture) gitProtocolBeforeExec() bool {
	envIdx := 0
	for _, typ := range c.Order {
		switch typ {
		case "env":
			if envIdx >= len(c.Envs) {
				return false
			}
			e := c.Envs[envIdx]
			envIdx++
			if e.Name == "GIT_PROTOCOL" {
				return true
			}
		case "exec":
			return false
		}
	}
	return false
}

// newHostKey generates an ephemeral ed25519 host key. Nothing persists it: a
// fresh key per run is fine because every client here disables host-key
// checking.
func newHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// serveOnce accepts exactly one connection, records its channel requests, and
// refuses the operation as soon as an exec arrives. It never runs git: the
// request capture is the whole point, so the client is expected to fail.
func serveOnce(ln net.Listener, hostKey ssh.Signer) *capture {
	c := &capture{}

	nConn, err := ln.Accept()
	if err != nil {
		c.Err = fmt.Errorf("accept: %w", err)
		return c
	}
	defer nConn.Close()
	if err := nConn.SetDeadline(time.Now().Add(sessionTimeout)); err != nil {
		c.Err = fmt.Errorf("set deadline: %w", err)
		return c
	}

	cfg := &ssh.ServerConfig{
		// Any key is accepted. Authorization is not what this spike tests.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	sConn, chans, globalReqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		c.Err = fmt.Errorf("handshake: %w", err)
		return c
	}
	defer sConn.Close()
	go ssh.DiscardRequests(globalReqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			c.Err = fmt.Errorf("accept channel: %w", err)
			return c
		}
		for req := range reqs {
			c.Order = append(c.Order, req.Type)
			switch req.Type {
			case "env":
				e, err := parseEnvReq(req.Payload)
				if err != nil {
					c.Err = fmt.Errorf("env payload: %w", err)
					ch.Close()
					return c
				}
				c.Envs = append(c.Envs, e)
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "exec":
				x, err := parseExecReq(req.Payload)
				if err != nil {
					c.Err = fmt.Errorf("exec payload: %w", err)
					ch.Close()
					return c
				}
				c.Exec = x.Command
				c.ExecSeen = true
				if req.WantReply {
					req.Reply(true, nil)
				}
				fmt.Fprint(ch.Stderr(), "patvault-spike: capture only, refusing\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 1}))
				ch.Close()
				return c
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}
	return c
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./spike/relay-ssh/ -v`
Expected: PASS — all six tests (four from Task 1, two here).

- [ ] **Step 5: Commit**

```bash
gofmt -w spike/relay-ssh/
git add spike/relay-ssh/server.go spike/relay-ssh/server_test.go
git commit -m "spike: single-connection ssh capture server for relay-ssh"
```

---

### Task 3: Drive real git — fetch scenario

The decisive check. Everything up to here proves the server records what a client sends; this proves what **git itself** sends.

**Files:**
- Create: `spike/relay-ssh/main.go`

**Interfaces:**
- Consumes: `capture`, `newHostKey`, `serveOnce` (Task 2).
- Produces:
  - `func pass(name string)` / `func fail(name, format string, a ...any)`
  - `func writeClientKey(dir string) (string, error)`
  - `func runGitIn(dir, keyPath string, args ...string) (string, error)`
  - `func scenario(hostKey ssh.Signer, run func(url string)) *capture`
  - `func scenarioFetch(hostKey, keyPath string)`

- [ ] **Step 1: Write the implementation**

There is no unit test for this task: the assertion *is* the program, exactly as in `spike/relay-v2/main.go`, and what it asserts about cannot be stubbed without destroying the point. Create `spike/relay-ssh/main.go`:

```go
// Command relay-ssh is a THROWAWAY spike that verifies what a real git client
// sends over SSH before the relay ever sees an exec: specifically that
// GIT_PROTOCOL=version=2 arrives as an env request ahead of the exec request.
// It is not part of the shipped binary.
//
// Run:
//
//	go run ./spike/relay-ssh
//
// No credentials and no network: it binds 127.0.0.1 and drives the local git.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

func pass(name string) { fmt.Printf("PASS: %s\n", name) }

func fail(name, format string, a ...any) {
	fmt.Printf("FAIL: %s: %s\n", name, fmt.Sprintf(format, a...))
	os.Exit(1)
}

// writeClientKey generates an ephemeral ed25519 key and writes it in OpenSSH
// private-key format for the ssh binary to use with -i.
func writeClientKey(dir string) (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "patvault-spike")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// runGitIn runs the real git binary against the spike server. GIT_SSH_COMMAND
// starts with "ssh" on purpose: git sniffs the ssh variant from that word and
// only adds "-o SendEnv=GIT_PROTOCOL" when it recognizes OpenSSH. That sniffing
// is part of what this spike tests, so do not bypass it with ssh.variant.
func runGitIn(dir, keyPath string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_SSH_COMMAND=ssh -i "+keyPath+
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"+
			" -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// scenario stands up a capture server, hands its ssh:// URL to run, and returns
// what the server saw. run is expected to fail (the server always refuses); its
// error is the caller's to ignore.
func scenario(hostKey ssh.Signer, run func(url string)) *capture {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	done := make(chan *capture, 1)
	go func() { done <- serveOnce(ln, hostKey) }()

	run(fmt.Sprintf("ssh://git@%s/owner/repo.git", ln.Addr().String()))

	select {
	case c := <-done:
		return c
	case <-time.After(sessionTimeout + 10*time.Second):
		fmt.Fprintln(os.Stderr, "server did not return a capture")
		os.Exit(1)
		return nil
	}
}

// scenarioFetch is the decisive check: a real git fetch must announce v2 via an
// env request before the exec.
func scenarioFetch(hostKey ssh.Signer, keyPath string) {
	const name = "fetch sends GIT_PROTOCOL=version=2 before exec"

	var out string
	c := scenario(hostKey, func(url string) {
		// ls-remote is the lightest command that triggers git-upload-pack.
		// It fails against the capture server; that is expected.
		out, _ = runGitIn(".", keyPath, "-c", "protocol.version=2", "ls-remote", url)
	})

	if c.Err != nil {
		fail(name, "capture error: %v (git output: %s)", c.Err, out)
	}
	if !c.ExecSeen {
		fail(name, "no exec request arrived; order=%v (git output: %s)", c.Order, out)
	}
	v, ok := c.gitProtocol()
	if !ok {
		fail(name, "git sent NO GIT_PROTOCOL env request; order=%v envs=%v "+
			"(the spec's v2 gate cannot work as written) (git output: %s)",
			c.Order, c.Envs, out)
	}
	if v != "version=2" {
		fail(name, "GIT_PROTOCOL=%q, want %q", v, "version=2")
	}
	if !c.gitProtocolBeforeExec() {
		fail(name, "GIT_PROTOCOL arrived but NOT before exec; order=%v", c.Order)
	}
	pass(name)
	fmt.Printf("      request order = %v\n", c.Order)
	fmt.Printf("      GIT_PROTOCOL  = %q\n", v)
	fmt.Printf("      exec          = %q\n", c.Exec)
}

func main() {
	dir, err := os.MkdirTemp("", "relay-ssh-spike")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tempdir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	hostKey, err := newHostKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "host key: %v\n", err)
		os.Exit(1)
	}
	keyPath, err := writeClientKey(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client key: %v\n", err)
		os.Exit(1)
	}

	scenarioFetch(hostKey, keyPath)

	fmt.Println("\nALL CHECKS PASSED — agent-facing v2 signalling validated")
}
```

- [ ] **Step 2: Run it**

Run: `go run ./spike/relay-ssh`
Expected: `PASS: fetch sends GIT_PROTOCOL=version=2 before exec`, followed by the observed order, value, and exec string. Record the exec string verbatim — Task 6 needs it.

If it FAILs, **do not patch around it**: a missing env request is the finding this spike exists to produce. Record the observed `order`/`envs` and stop; the spec's §"Wire protocol" needs revision before the relay plan is written.

- [ ] **Step 3: Verify vet is clean**

Run: `go vet ./spike/relay-ssh/`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
gofmt -w spike/relay-ssh/
git add spike/relay-ssh/main.go
git commit -m "spike: verify git signals v2 via ssh env request before exec"
```

---

### Task 4: Negative case — protocol v0 must be distinguishable

The v2 gate has to *refuse* a non-v2 fetch (spec lines 257–262), which means the absence of v2 must be detectable, not just its presence. A gate that cannot tell the two apart fails open.

**Files:**
- Modify: `spike/relay-ssh/main.go` (add `scenarioFetchV0`, call it from `main`)

**Interfaces:**
- Consumes: `scenario`, `runGitIn`, `pass`, `fail` (Task 3).
- Produces: `func scenarioFetchV0(hostKey ssh.Signer, keyPath string)`

- [ ] **Step 1: Add the scenario**

Add to `spike/relay-ssh/main.go`, after `scenarioFetch`:

```go
// scenarioFetchV0 pins the negative case. The relay must refuse a fetch that
// did not announce v2, so "not v2" has to be distinguishable from v2. This
// asserts the weaker, sufficient property — that git does not claim version=2
// under protocol.version=0 — rather than guessing whether git omits the env
// request entirely or sends a different value.
func scenarioFetchV0(hostKey ssh.Signer, keyPath string) {
	const name = "protocol v0 fetch does not announce version=2"

	var out string
	c := scenario(hostKey, func(url string) {
		out, _ = runGitIn(".", keyPath, "-c", "protocol.version=0", "ls-remote", url)
	})

	if c.Err != nil {
		fail(name, "capture error: %v (git output: %s)", c.Err, out)
	}
	if !c.ExecSeen {
		fail(name, "no exec request arrived; order=%v (git output: %s)", c.Order, out)
	}
	v, ok := c.gitProtocol()
	if ok && v == "version=2" {
		fail(name, "git announced version=2 under protocol.version=0 — "+
			"the v2 gate cannot distinguish v0 from v2; order=%v", c.Order)
	}
	pass(name)
	if ok {
		fmt.Printf("      GIT_PROTOCOL  = %q (sent, but not version=2)\n", v)
	} else {
		fmt.Printf("      GIT_PROTOCOL  = <not sent>\n")
	}
	fmt.Printf("      request order = %v\n", c.Order)
	fmt.Printf("      exec          = %q\n", c.Exec)
}
```

- [ ] **Step 2: Call it from main**

In `spike/relay-ssh/main.go`, change:

```go
	scenarioFetch(hostKey, keyPath)
```

to:

```go
	scenarioFetch(hostKey, keyPath)
	scenarioFetchV0(hostKey, keyPath)
```

- [ ] **Step 3: Run it**

Run: `go run ./spike/relay-ssh`
Expected: both scenarios PASS. Record whether `GIT_PROTOCOL` is absent or merely different under v0 — the relay's gate is written against whichever it is.

- [ ] **Step 4: Commit**

```bash
gofmt -w spike/relay-ssh/
git add spike/relay-ssh/main.go
git commit -m "spike: confirm protocol v0 fetch is distinguishable from v2"
```

---

### Task 5: Push scenario — the receive-pack exec string

The spec's exec parser must handle `git-receive-pack` (spec lines 213, 233), and its path-normalization hazards (leading `/`, trailing `.git`, lines 218–222) are stated from reasoning, not observation. This captures the real string. It also records, for free, whether git announces `GIT_PROTOCOL` on a push — informational, since receive-pack has no v2.

**Files:**
- Modify: `spike/relay-ssh/main.go` (add `scenarioPush`, call it from `main`)

**Interfaces:**
- Consumes: `scenario`, `runGitIn`, `pass`, `fail` (Task 3).
- Produces: `func scenarioPush(hostKey ssh.Signer, keyPath, dir string)`

- [ ] **Step 1: Add the scenario**

Add to `spike/relay-ssh/main.go`, after `scenarioFetchV0`:

```go
// scenarioPush captures the exec string a real push sends. The spec's exec
// parser must accept git-receive-pack and normalize the path; this records what
// it will actually receive rather than what we assume.
func scenarioPush(hostKey ssh.Signer, keyPath, dir string) {
	const name = "push sends git-receive-pack exec"

	repo := filepath.Join(dir, "pushsrc")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		fail(name, "mkdir: %v", err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "spike@example.invalid"},
		{"config", "user.name", "patvault spike"},
		{"commit", "-q", "--allow-empty", "-m", "spike"},
	} {
		if out, err := runGitIn(repo, keyPath, args...); err != nil {
			fail(name, "git %v: %v (%s)", args, err, out)
		}
	}

	var out string
	c := scenario(hostKey, func(url string) {
		out, _ = runGitIn(repo, keyPath, "push", url, "HEAD:refs/heads/main")
	})

	if c.Err != nil {
		fail(name, "capture error: %v (git output: %s)", c.Err, out)
	}
	if !c.ExecSeen {
		fail(name, "no exec request arrived; order=%v (git output: %s)", c.Order, out)
	}
	if !strings.HasPrefix(c.Exec, "git-receive-pack ") {
		fail(name, "exec = %q, want a git-receive-pack command", c.Exec)
	}
	pass(name)
	v, ok := c.gitProtocol()
	if ok {
		fmt.Printf("      GIT_PROTOCOL  = %q\n", v)
	} else {
		fmt.Printf("      GIT_PROTOCOL  = <not sent>\n")
	}
	fmt.Printf("      request order = %v\n", c.Order)
	fmt.Printf("      exec          = %q\n", c.Exec)
}
```

- [ ] **Step 2: Add the strings import and call it from main**

In `spike/relay-ssh/main.go`, add `"strings"` to the import block, then change:

```go
	scenarioFetch(hostKey, keyPath)
	scenarioFetchV0(hostKey, keyPath)
```

to:

```go
	scenarioFetch(hostKey, keyPath)
	scenarioFetchV0(hostKey, keyPath)
	scenarioPush(hostKey, keyPath, dir)
```

- [ ] **Step 3: Run it**

Run: `go run ./spike/relay-ssh`
Expected: three PASS lines, then `ALL CHECKS PASSED`. Record both exec strings — fetch and push — verbatim.

- [ ] **Step 4: Verify the whole spike is clean**

Run: `go build ./spike/relay-ssh/ && go vet ./spike/relay-ssh/ && go test ./spike/relay-ssh/`
Expected: no build output, no vet output, `ok  github.com/quells-bot/patvault/spike/relay-ssh`.

- [ ] **Step 5: Commit**

```bash
gofmt -w spike/relay-ssh/
git add spike/relay-ssh/main.go
git commit -m "spike: capture the real git-receive-pack exec string"
```

---

### Task 6: README and findings note

The v2 spike's findings note is the model here, including its hard-won lesson: record only what the program actually printed, and mark anything asserted-but-not-printed as such.

**Files:**
- Create: `spike/relay-ssh/README.md`
- Create: `docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md`
- Modify: `docs/superpowers/specs/2026-07-15-relay-design.md` (only if a check FAILed)

**Interfaces:**
- Consumes: the observed output of Tasks 3–5.
- Produces: no code.

- [ ] **Step 1: Write the README**

Create `spike/relay-ssh/README.md`:

```markdown
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
3. A real `git push` sends a `git-receive-pack` exec, and the exact exec string
   is recorded for `internal/relay/exec.go`'s parser.

The server accepts any public key and refuses every exec with exit-status 1, so
git always reports failure. That is expected: the captured requests are the
result, not git's exit code.
```

- [ ] **Step 2: Write the findings note**

Create `docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md` using the structure of `2026-07-16-relay-v2-spike-findings.md`:

- A **STATUS** banner stating whether the run happened and the outcome.
- A **Provenance** section: who ran it, on what git/ssh versions (`git --version`, `ssh -V`), and that it needs no credentials — so unlike the v2 spike, anyone can reproduce it.
- A **Results** table, one row per scenario, `PASS`/`FAIL` with the observed order, `GIT_PROTOCOL` value, and exec string pasted verbatim from the output.
- **Surprises / deviations from the spec** — in particular, compare the observed exec strings against the spec's assumptions at lines 210–226: does the path arrive with a leading `/`? with `.git`? single-quoted? Each answer is a fact `internal/relay/exec.go` will be built on.
- A **Conclusion** stating explicitly whether the "require v2" decision survives.

Mark anything the program asserted but did not print as asserted-but-not-captured. Do not write down a value the output does not contain.

- [ ] **Step 3: Update the spec if a check FAILed**

If Task 3 FAILed (no env request, or not before the exec), the spec's §"Wire protocol" v2-signalling mechanism is wrong. Revise it and its §Testing "protocol v2 gate" bullet, and say so in the findings Conclusion. If everything PASSed, add a line to §"Wire protocol" citing the note as confirmation, matching how the auth-scheme correction cites the v2 spike.

- [ ] **Step 4: Commit**

```bash
git add spike/relay-ssh/README.md docs/superpowers/notes/2026-07-16-relay-ssh-spike-findings.md docs/superpowers/specs/2026-07-15-relay-design.md
git commit -m "spike: record relay ssh GIT_PROTOCOL findings"
```

---

## Disposition of spike code

Throwaway, with one exception worth keeping in view: `serveOnce`'s request loop is the shape `internal/relay`'s SSH server needs — accept a session channel, handle `env` before `exec`, reject everything else, answer with `exit-status`. It is not production code (it accepts any key, captures instead of serving, and handles exactly one connection), but it is a working reference for the channel-request handling the relay must implement, the same way `spike/relay-v2/pktline.go` is the reference for `internal/relay/pktline.go`.

## What this spike does NOT cover

Named so the relay plan does not mistake this for broader coverage:

- **Authorization.** The server accepts any public key. The allowlist (spec §"Threat model") is untested here.
- **The exec parser.** This captures the exec *string*; it does not test `parseExec`'s quoting, normalization, or shape checks. That is the relay plan's job — but it should be written against the strings this spike recorded.
- **Any upstream behavior.** No HTTP, no GitHub. The upstream half is `spike/relay-v2/`.
- **The relay's forwarding of `Git-Protocol` upstream.** This proves the relay *can learn* the version, not that it forwards it correctly.
- **The three follow-ups** recorded in the spec's §"Unverified assumptions": real-GitHub push, pack-body streaming and sideband pass-through, and the status→message mapping in §Errors.
