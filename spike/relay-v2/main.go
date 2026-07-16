// Command relay-v2 is a THROWAWAY spike that validates patvault's relay v2
// protocol assumptions against real GitHub. It is not part of the shipped
// binary; its pkt-line helpers inform internal/relay/pktline.go.
//
// Run:
//   SPIKE_REPO=owner/repo SPIKE_TOKEN=<fine-grained PAT> go run ./spike/relay-v2
// Use a private repo (or set SPIKE_PUBLIC=1 to skip the no-auth check).
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func pass(name string) { fmt.Printf("PASS: %s\n", name) }

func fail(name, format string, a ...any) {
	fmt.Printf("FAIL: %s: %s\n", name, fmt.Sprintf(format, a...))
	os.Exit(1)
}

func doGET(url, token, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.43.0")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return http.DefaultClient.Do(req)
}

func doPOST(url, token, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "git/2.43.0")
	return http.DefaultClient.Do(req)
}

// readUntilFlush reads data pkt-lines until the next flush-pkt, returning the
// data payloads (delim-pkts are skipped).
func readUntilFlush(r io.Reader) ([][]byte, error) {
	var out [][]byte
	for {
		p, kind, err := readPktLine(r)
		if err != nil {
			return out, err
		}
		switch kind {
		case pktFlush:
			return out, nil
		case pktData:
			out = append(out, p)
		}
	}
}

func checkAdvertisement(base, token string) {
	const name = "advertisement (upload-pack v2)"
	resp, err := doGET(base+"/info/refs?service=git-upload-pack", token,
		"application/x-git-upload-pack-advertisement")
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		fail(name, "content-type %q (want advertisement)", ct)
	}

	// First pkt-line is the service banner the SSH transport does NOT use.
	p, kind, err := readPktLine(resp.Body)
	if err != nil || kind != pktData || !strings.HasPrefix(string(p), "# service=git-upload-pack") {
		fail(name, "banner: p=%q kind=%d err=%v", p, kind, err)
	}
	// A flush terminates the banner.
	if _, kind, err = readPktLine(resp.Body); err != nil || kind != pktFlush {
		fail(name, "expected flush after banner: kind=%d err=%v", kind, err)
	}
	// The v2 advertisement follows, up to the next flush.
	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading advertisement: %v", err)
	}
	if len(lines) == 0 || strings.TrimSpace(string(lines[0])) != "version 2" {
		first := "<none>"
		if len(lines) > 0 {
			first = string(lines[0])
		}
		fail(name, "first advertisement line %q (want 'version 2')", first)
	}
	caps := map[string]bool{}
	for _, l := range lines[1:] {
		key := strings.SplitN(strings.TrimSpace(string(l)), "=", 2)[0]
		caps[key] = true
	}
	for _, need := range []string{"ls-refs", "fetch"} {
		if !caps[need] {
			fail(name, "missing capability %q", need)
		}
	}
	pass(name)
}

func checkNoAuth(base string) {
	const name = "no-auth rejected"
	resp, err := doGET(base+"/info/refs?service=git-upload-pack", "", "")
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	// The security-relevant invariant: an unauthenticated request must NOT
	// receive the advertisement. GitHub answers 401 or 404 for a private repo;
	// a 200 means the repo is public (re-run with SPIKE_PUBLIC=1) or, worse,
	// that unauth reached the advertisement.
	if resp.StatusCode == 200 {
		fail(name, "status 200 — unauthenticated request was NOT rejected "+
			"(is the repo public? set SPIKE_PUBLIC=1 to skip this check)")
	}
	pass(name)
	fmt.Printf("      unauthenticated status = %d\n", resp.StatusCode)
}

// lsRefs sends a v2 ls-refs command and returns the object id of HEAD.
func lsRefs(base, token string) string {
	const name = "ls-refs round-trip"
	var body bytes.Buffer
	writePktLine(&body, "command=ls-refs\n")
	writePktLine(&body, "object-format=sha1\n")
	writeDelim(&body)
	writePktLine(&body, "peel\n")
	writePktLine(&body, "symrefs\n")
	writePktLine(&body, "ref-prefix HEAD\n")
	writeFlush(&body)

	resp, err := doPOST(base+"/git-upload-pack", token,
		"application/x-git-upload-pack-request", body.Bytes())
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading refs: %v", err)
	}
	var head string
	for _, l := range lines {
		fields := strings.Fields(string(l))
		if len(fields) >= 2 && fields[1] == "HEAD" {
			head = fields[0]
			break
		}
	}
	if head == "" {
		fail(name, "no HEAD ref found in %d ref lines", len(lines))
	}
	pass(name)
	fmt.Printf("      HEAD = %s\n", head)
	return head
}

func main() {
	repo := os.Getenv("SPIKE_REPO")
	token := os.Getenv("SPIKE_TOKEN")
	if repo == "" || token == "" {
		fmt.Fprintln(os.Stderr, "set SPIKE_REPO=owner/repo and SPIKE_TOKEN=<fine-grained PAT>")
		os.Exit(2)
	}
	base := "https://github.com/" + repo + ".git"

	checkAdvertisement(base, token)
	if os.Getenv("SPIKE_PUBLIC") == "" {
		checkNoAuth(base)
	} else {
		fmt.Println("SKIP: no-auth rejected (SPIKE_PUBLIC set)")
	}
	head := lsRefs(base, token)
	_ = head

	fmt.Println("\n(advertisement + ls-refs checks passed)")
}