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
