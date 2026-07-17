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
	"strings"
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

// defaultRepoPath is the URL path the protocol-version scenarios use. It is
// spelled out at each call site rather than baked into scenario() because the
// ".git" here is the *caller's* choice: git echoes the URL path into the exec
// string verbatim, so a suffix baked in here would look like git's doing. See
// scenarioExecPaths.
const defaultRepoPath = "/owner/repo.git"

// scenario stands up a capture server, hands it an ssh:// URL with repoPath as
// the path component, and returns what the server saw. run is expected to fail
// (the server always refuses); its error is the caller's to ignore.
func scenario(hostKey ssh.Signer, repoPath string, run func(url string)) *capture {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	done := make(chan *capture, 1)
	go func() { done <- serveOnce(ln, hostKey) }()

	run(fmt.Sprintf("ssh://git@%s%s", ln.Addr().String(), repoPath))

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
	c := scenario(hostKey, defaultRepoPath, func(url string) {
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

// scenarioFetchV0 pins the negative case. The relay must refuse a fetch that
// did not announce v2, so "not v2" has to be distinguishable from v2. This
// asserts the weaker, sufficient property — that git does not claim version=2
// under protocol.version=0 — rather than guessing whether git omits the env
// request entirely or sends a different value.
func scenarioFetchV0(hostKey ssh.Signer, keyPath string) {
	const name = "protocol v0 fetch does not announce version=2"

	var out string
	c := scenario(hostKey, defaultRepoPath, func(url string) {
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

// scenarioFetchV1 pins the case that decides how the v2 gate is written. Unlike
// v0, git DOES send GIT_PROTOCOL under protocol.version=1 — it just carries
// version=1. A gate keyed on the presence of the env request therefore admits a
// v1 client as if it were v2 and pumps a v1 negotiation into the v2 stateless
// path; the gate must compare the value.
//
// This asserts more than scenarioFetchV0 does deliberately. The safety property
// (never announces version=2) is the same, but the presence-and-value assertion
// is what the relay's gate is written against, so it is pinned here rather than
// left to a reader's assumption.
func scenarioFetchV1(hostKey ssh.Signer, keyPath string) {
	const name = "protocol v1 fetch announces version=1, not version=2"

	var out string
	c := scenario(hostKey, defaultRepoPath, func(url string) {
		out, _ = runGitIn(".", keyPath, "-c", "protocol.version=1", "ls-remote", url)
	})

	if c.Err != nil {
		fail(name, "capture error: %v (git output: %s)", c.Err, out)
	}
	if !c.ExecSeen {
		fail(name, "no exec request arrived; order=%v (git output: %s)", c.Order, out)
	}
	v, ok := c.gitProtocol()
	if ok && v == "version=2" {
		fail(name, "git announced version=2 under protocol.version=1 — "+
			"the v2 gate cannot distinguish v1 from v2; order=%v", c.Order)
	}
	if !ok {
		fail(name, "git sent NO GIT_PROTOCOL env request under protocol.version=1; "+
			"order=%v envs=%v (expected version=1 — if this git really omits it, the "+
			"findings note's presence-vs-value claim needs revisiting) (git output: %s)",
			c.Order, c.Envs, out)
	}
	if v != "version=1" {
		fail(name, "GIT_PROTOCOL=%q, want %q", v, "version=1")
	}
	pass(name)
	fmt.Printf("      GIT_PROTOCOL  = %q (sent, but not version=2 —\n", v)
	fmt.Printf("                      a presence-only v2 gate would fail open here)\n")
	fmt.Printf("      request order = %v\n", c.Order)
	fmt.Printf("      exec          = %q\n", c.Exec)
}

// execPathCases pin what parseExec will actually be handed. Each drives a real
// fetch at a URL whose path is `path`, and requires the captured exec string to
// be exactly `want`.
//
// The first two are the correction to this spike's original findings note, which
// claimed "git 2.53.0 appends .git to the repository path". It does not: it
// echoes the URL's path through verbatim. The suffix is the user's remote URL's
// business, so parseExec must tolerate its presence AND its absence — the reason
// the spec normalizes, but not the reason the note gave.
//
// The apostrophe case is the one with teeth. Git emits POSIX single-quote
// escaping — close, escaped quote, reopen — so the exec string for it's.git is
// literally: git-upload-pack '/owner/it'\”s.git'
// A parser that strips the first and last quote yields /owner/it'\”s.git, not
// /owner/it's.git. This is what the spec's hazard 1 ("strip one level of shell
// quoting rather than naive whitespace-splitting", line 210) is protecting
// against, and nothing verified it until now. Note the spec's hazard 3 wording,
// "strip the surrounding quotes" (line 218), describes exactly the naive parse
// that gets this wrong; parseExec needs a shell-word split.
//
// These paths are not valid GitHub repo names, so the spec's shape check (line
// 223) rejects all but the first two regardless. They are here to pin the
// quoting contract, not to suggest the relay should serve them.
var execPathCases = []struct {
	what string
	path string // path component of the ssh:// URL git is pointed at
	want string // the exec string the server must receive, verbatim
}{
	{"suffixed path passes through", "/owner/repo.git", `git-upload-pack '/owner/repo.git'`},
	{"unsuffixed path stays unsuffixed", "/owner/repo", `git-upload-pack '/owner/repo'`},
	{"space survives inside quotes", "/owner/my repo.git", `git-upload-pack '/owner/my repo.git'`},
	{"apostrophe is POSIX-escaped", "/owner/it's.git", `git-upload-pack '/owner/it'\''s.git'`},
}

// scenarioExecPaths proves the exec path is the URL path and nothing else.
func scenarioExecPaths(hostKey ssh.Signer, keyPath string) {
	const name = "exec path is the URL path, verbatim"

	got := make([]string, len(execPathCases))
	for i, tc := range execPathCases {
		var out string
		c := scenario(hostKey, tc.path, func(url string) {
			out, _ = runGitIn(".", keyPath, "-c", "protocol.version=2", "ls-remote", url)
		})

		if c.Err != nil {
			fail(name, "%s: capture error: %v (git output: %s)", tc.what, c.Err, out)
		}
		if !c.ExecSeen {
			fail(name, "%s: no exec request arrived; order=%v (git output: %s)",
				tc.what, c.Order, out)
		}
		if c.Exec != tc.want {
			fail(name, "%s: exec = %q, want %q", tc.what, c.Exec, tc.want)
		}
		got[i] = c.Exec
	}
	pass(name)
	for i, tc := range execPathCases {
		fmt.Printf("      %-34s %q\n", tc.what+":", got[i])
	}
}

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
	c := scenario(hostKey, defaultRepoPath, func(url string) {
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
	scenarioFetchV0(hostKey, keyPath)
	scenarioFetchV1(hostKey, keyPath)
	scenarioExecPaths(hostKey, keyPath)
	scenarioPush(hostKey, keyPath, dir)

	fmt.Println("\nALL CHECKS PASSED — agent-facing v2 signalling and push exec validated")
}
