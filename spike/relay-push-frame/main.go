// Command relay-push-frame is a THROWAWAY probe answering one question:
//
//	When a real git client pushes over SSH, how does the relay know where the
//	client's request body ENDS?
//
// The spec's push bridge says "relay the client's ref-update commands +
// packfile to POST .../git-receive-pack". An HTTP request body must terminate.
// Over SSH git sends commands + flush + a raw packfile, then waits for
// report-status. If nothing marks the end of the pack, the relay cannot close
// the POST body without parsing the pack itself — which contradicts the spec's
// "the relay does not need to understand packs".
//
// This stands up an SSH server that advertises an empty repo, lets a real git
// push send its commands and pack, and then reports exactly what arrives after
// the pack: EOF, a flush-pkt, or nothing at all.
//
// No credentials, no network: binds 127.0.0.1 and drives the local git.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const zeroOID = "0000000000000000000000000000000000000000"

func main() {
	dir, err := os.MkdirTemp("", "relay-push-frame")
	if err != nil {
		die("tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	hostKey, keyPath := setupKeys(dir)
	repo := makeRepo(dir, keyPath)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		die("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() { defer close(done); serve(ln, hostKey) }()

	url := fmt.Sprintf("ssh://git@%s/owner/repo.git", ln.Addr().String())
	out, _ := runGit(repo, keyPath, "push", url, "HEAD:refs/heads/main")
	fmt.Printf("\n--- git said ---\n%s\n", strings.TrimSpace(out))
	<-done
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func setupKeys(dir string) (ssh.Signer, string) {
	_, hpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("host key: %v", err)
	}
	hostKey, err := ssh.NewSignerFromKey(hpriv)
	if err != nil {
		die("host signer: %v", err)
	}
	_, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die("client key: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(cpriv, "probe")
	if err != nil {
		die("marshal client key: %v", err)
	}
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		die("write client key: %v", err)
	}
	return hostKey, keyPath
}

func runGit(dir, keyPath string, args ...string) (string, error) {
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

// makeRepo builds a local repo with one commit that has real content, so the
// pack is not degenerately small.
func makeRepo(dir, keyPath string) string {
	repo := filepath.Join(dir, "src")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		die("mkdir: %v", err)
	}
	body := strings.Repeat("patvault push framing probe\n", 500)
	if err := os.WriteFile(filepath.Join(repo, "data.txt"), []byte(body), 0o644); err != nil {
		die("write file: %v", err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "probe@example.invalid"},
		{"config", "user.name", "probe"},
		{"add", "data.txt"},
		{"commit", "-q", "-m", "probe"},
	} {
		if out, err := runGit(repo, keyPath, args...); err != nil {
			die("git %v: %v (%s)", args, err, out)
		}
	}
	return repo
}

func writePkt(w io.Writer, s string) {
	fmt.Fprintf(w, "%04x%s", len(s)+4, s)
}

func serve(ln net.Listener, hostKey ssh.Signer) {
	nConn, err := ln.Accept()
	if err != nil {
		die("accept: %v", err)
	}
	defer nConn.Close()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	sConn, chans, globalReqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		die("handshake: %v", err)
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
			die("accept channel: %v", err)
		}
		for req := range reqs {
			switch req.Type {
			case "env":
				req.Reply(true, nil)
			case "exec":
				req.Reply(true, nil)
				handlePush(ch)
				return
			default:
				req.Reply(false, nil)
			}
		}
	}
}

// handlePush advertises an empty repo, then reports what the client sends and,
// critically, what (if anything) marks the end of it.
func handlePush(ch ssh.Channel) {
	// Advertise an empty repo: git will send a create command + a pack.
	writePkt(ch, zeroOID+" capabilities^{}\x00report-status delete-refs side-band-64k object-format=sha1 agent=patvault-probe\n")
	io.WriteString(ch, "0000")

	// Read the ref-update commands up to their terminating flush.
	fmt.Println("=== client -> server ===")
	var cmds int
	for {
		p, isFlush, err := readPkt(ch)
		if err != nil {
			fmt.Printf("error reading commands: %v\n", err)
			return
		}
		if isFlush {
			fmt.Printf("commands: %d, terminated by flush-pkt\n", cmds)
			break
		}
		cmds++
		fmt.Printf("  command pkt: %q\n", sanitize(string(p)))
	}

	// Everything after the commands' flush is the raw pack. Drain it and watch
	// for what ends it. A timeout distinguishes "client closed" from "client is
	// waiting for us".
	body, ended := drain(ch)

	fmt.Println("=== after the commands' flush ===")
	fmt.Printf("  raw bytes read after flush: %d\n", len(body))
	fmt.Printf("  how the stream ended:       %s\n", ended)
	fmt.Printf("  starts with PACK magic:     %v\n", strings.HasPrefix(string(body), "PACK"))
	fmt.Printf("  pack is COMPLETE:           %s\n", verifyPack(body))
	fmt.Println()
	fmt.Println("=== VERDICT ===")
	if ended == "EOF" {
		fmt.Println("  git CLOSED its write side after the pack (half-close; it still reads")
		fmt.Println("  the response). The relay can stream client->POST body until EOF and")
		fmt.Println("  never parse the pack. The spec's 'thin pump' premise HOLDS for push.")
	} else {
		fmt.Println("  git sent the pack and then WAITED — no EOF, no terminator.")
		fmt.Println("  => the relay CANNOT know where the pack ends without parsing it.")
		fmt.Println("     The spec's 'relay does not need to understand packs' does NOT")
		fmt.Println("     hold for the push direction.")
	}

	// Report success so git exits cleanly. The client asked for side-band-64k
	// (see its command pkt), so the report-status MUST be framed on band 1 —
	// sending it raw earns "protocol error: bad band".
	var rep strings.Builder
	writePkt(&rep, "unpack ok\n")
	writePkt(&rep, "ok refs/heads/main\n")
	rep.WriteString("0000")
	writePkt(ch, "\x01"+rep.String())
	io.WriteString(ch, "0000")
	ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	ch.Close()
}

// drain reads until EOF or until the client goes quiet, returning the bytes that
// arrived and what ended the stream.
func drain(ch ssh.Channel) ([]byte, string) {
	type res struct {
		b   []byte
		err error
	}
	// Read in a goroutine so a blocked read (client waiting on us) is
	// observable as a timeout rather than hanging the probe forever.
	out := make(chan res, 1)
	var body []byte
	for {
		go func() {
			buf := make([]byte, 32*1024)
			n, err := ch.Read(buf)
			out <- res{buf[:n], err}
		}()
		select {
		case r := <-out:
			body = append(body, r.b...)
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return body, "EOF"
				}
				return body, fmt.Sprintf("error: %v", r.err)
			}
		case <-time.After(3 * time.Second):
			// No more bytes and no EOF: the client is waiting on us.
			return body, "BLOCKED (no EOF; client is waiting for a response)"
		}
	}
}

// verifyPack is the check that turns "we saw EOF" into "we saw a COMPLETE pack,
// then EOF". If git had aborted mid-pack we would also observe EOF, and the
// verdict would be a lie. git index-pack validates the object count and the
// trailing checksum, so it fails on a truncated pack.
func verifyPack(body []byte) string {
	dir, err := os.MkdirTemp("", "verify-pack")
	if err != nil {
		return fmt.Sprintf("inconclusive (tempdir: %v)", err)
	}
	defer os.RemoveAll(dir)

	if out, err := runGit(dir, "", "init", "-q", "--bare"); err != nil {
		return fmt.Sprintf("inconclusive (git init: %v: %s)", err, out)
	}
	packPath := filepath.Join(dir, "in.pack")
	if err := os.WriteFile(packPath, body, 0o644); err != nil {
		return fmt.Sprintf("inconclusive (write: %v)", err)
	}
	cmd := exec.Command("git", "index-pack", "-v", packPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Sprintf("NO — git index-pack rejected it: %v (%s)",
			err, strings.TrimSpace(string(out)))
	}
	return "yes — git index-pack accepted it (object count + trailing checksum valid)"
}

func readPkt(r io.Reader) ([]byte, bool, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	var n int
	if _, err := fmt.Sscanf(string(hdr[:]), "%04x", &n); err != nil {
		return nil, false, fmt.Errorf("bad pkt header %q: %w", hdr[:], err)
	}
	if n == 0 {
		return nil, true, nil
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, false, err
	}
	return buf, false, nil
}

func sanitize(s string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\x00", "\\0")
}
