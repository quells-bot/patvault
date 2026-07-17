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
