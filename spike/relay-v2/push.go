package main

// Push-side checks for the relay spike. These cover the spec's first
// "Unverified assumption": push against real GitHub was never tested, so the
// git-receive-pack advertisement framing, the auth scheme on that endpoint, and
// the commands+pack / report-status round-trip are all unobserved.
//
// Split in two tiers because only the second one writes:
//
//   Tier 1 (read-only): the advertisement GET and the auth-scheme comparison.
//   Tier 2 (writes):    a real push of an empty commit to a scratch ref, then
//                       a delete of that ref. Gated behind SPIKE_PUSH=1.
//
// Tier 1 runs whenever the fetch checks run. Tier 2 never runs by accident.

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// zeroOID is the all-zeros object id: "no such ref" on either side of a
// receive-pack command. As the old value it means create; as the new value,
// delete.
const zeroOID = "0000000000000000000000000000000000000000"

// authMode selects how a request carries the PAT. The v2 spike found GitHub's
// Git transport rejects Bearer on git-upload-pack while accepting Basic; this
// exists to ask the same question of git-receive-pack rather than assume the
// answer carries over.
type authMode int

const (
	authNone authMode = iota
	authBasic
	authBearer
)

func (m authMode) String() string {
	switch m {
	case authBasic:
		return "Basic x-access-token:<PAT>"
	case authBearer:
		return "Bearer <PAT>"
	default:
		return "none"
	}
}

// doGETAuth issues the advertisement GET under a chosen auth scheme.
func doGETAuth(url string, mode authMode, token, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	switch mode {
	case authBasic:
		req.SetBasicAuth("x-access-token", token)
	case authBearer:
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("User-Agent", "git/2.43.0")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return http.DefaultClient.Do(req)
}

// checkReceivePackAdvertisement is tier 1's main event: the framing of the
// git-receive-pack advertisement. The relay must strip the same banner+flush
// prefix it strips for upload-pack, and the SSH transport never sends one.
//
// Note this deliberately sends Git-Protocol: version=2 and expects to be
// ignored: receive-pack has no v2, so the advertisement should come back in the
// classic ref-list form regardless. That is the spec's "push is unaffected by
// the version gate" claim, and it is checked here rather than assumed.
func checkReceivePackAdvertisement(base, token string) []string {
	const name = "advertisement (receive-pack)"
	resp, err := doGETAuth(base+"/info/refs?service=git-receive-pack", authBasic, token,
		"application/x-git-receive-pack-advertisement")
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-git-receive-pack-advertisement" {
		fail(name, "content-type %q (want advertisement)", ct)
	}

	p, kind, err := readPktLine(resp.Body)
	if err != nil || kind != pktData || !strings.HasPrefix(string(p), "# service=git-receive-pack") {
		fail(name, "banner: p=%q kind=%d err=%v", p, kind, err)
	}
	banner := strings.TrimSpace(string(p))
	if _, kind, err = readPktLine(resp.Body); err != nil || kind != pktFlush {
		fail(name, "expected flush after banner: kind=%d err=%v", kind, err)
	}

	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading advertisement: %v", err)
	}
	if len(lines) == 0 {
		fail(name, "advertisement had no ref lines")
	}
	// The first ref line carries the capability list after a NUL.
	first := string(lines[0])
	var caps []string
	if i := strings.IndexByte(first, 0); i >= 0 {
		caps = strings.Fields(first[i+1:])
		first = first[:i]
	} else {
		fail(name, "first ref line %q has no NUL-separated capability list", first)
	}
	if strings.HasPrefix(first, "version 2") {
		fail(name, "receive-pack answered a v2 advertisement (%q) — the spec's "+
			"'push is unaffected by the version gate' claim needs revisiting", first)
	}

	pass(name)
	fmt.Printf("      banner        = %q\n", banner)
	fmt.Printf("      first ref     = %q\n", first)
	fmt.Printf("      capabilities  = %s\n", strings.Join(caps, " "))
	return caps
}

// checkReceivePackAuth compares auth schemes on the receive-pack endpoint.
//
// Only two properties are asserted: Basic works, and unauthenticated does not.
// Bearer's status is RECORDED, not asserted. The relay uses Basic either way, so
// pinning "Bearer is rejected here too" would buy nothing and would fail
// spuriously if GitHub ever widened Bearer support — a spike should not assert
// what its caller does not depend on.
func checkReceivePackAuth(base, token string) {
	const name = "receive-pack auth scheme"
	url := base + "/info/refs?service=git-receive-pack"

	status := func(mode authMode) int {
		tok := token
		if mode == authNone {
			tok = ""
		}
		resp, err := doGETAuth(url, mode, tok, "")
		if err != nil {
			fail(name, "%v: request error: %v", mode, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	none := status(authNone)
	bearer := status(authBearer)
	basic := status(authBasic)

	if basic != 200 {
		fail(name, "Basic got status %d (want 200) — the relay's upstream auth "+
			"does not work on the push endpoint", basic)
	}
	if none == 200 {
		fail(name, "unauthenticated got status 200 — the repo is public, so this "+
			"run proves nothing about auth (use a private repo)")
	}
	pass(name)
	fmt.Printf("      none          = %d\n", none)
	fmt.Printf("      Bearer        = %d (recorded, not asserted)\n", bearer)
	fmt.Printf("      Basic         = %d\n", basic)
}

// git runs a git command in dir and returns trimmed stdout.
func git(name, dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fail(name, "git %s: %v (%s)", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// receivePack POSTs a commands+pack request and returns the report-status
// payload lines. pack may be empty for a delete-only request.
func receivePack(name, base, token, cmdLine string, pack []byte) []string {
	var body bytes.Buffer
	// Capabilities ride on the first (here, only) command line after a NUL.
	// side-band-64k is deliberately NOT requested: without it the report-status
	// comes back as plain pkt-lines. Sideband pass-through is a separate
	// unverified assumption and is not what this checks.
	if err := writePktLine(&body, cmdLine+"\x00report-status\n"); err != nil {
		fail(name, "writing command: %v", err)
	}
	if err := writeFlush(&body); err != nil {
		fail(name, "writing flush: %v", err)
	}
	body.Write(pack)

	resp, err := doPOST(base+"/git-receive-pack", token,
		"application/x-git-receive-pack-request", body.Bytes())
	if err != nil {
		fail(name, "request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(name, "status %d (want 200)", resp.StatusCode)
	}
	lines, err := readUntilFlush(resp.Body)
	if err != nil {
		fail(name, "reading report-status: %v", err)
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.TrimSpace(string(l))
	}
	return out
}

// checkPush is tier 2: a real push to a real private repo. It clones, builds an
// empty commit, packs exactly that commit, and POSTs it to a scratch ref — then
// deletes the ref. The empty commit is the point: the bridge does not care what
// is in the pack, and pack-body streaming is a different follow-up.
func checkPush(base, token, repo string) {
	const name = "push round-trip (report-status)"

	dir, err := os.MkdirTemp("", "relay-push-spike")
	if err != nil {
		fail(name, "tempdir: %v", err)
	}
	defer os.RemoveAll(dir)

	// The clone URL carries the token, so it lands in the temp clone's config.
	// The temp dir is removed on return; nothing here is ever committed.
	cloneURL := "https://x-access-token:" + token + "@github.com/" + repo + ".git"
	git(name, "", "clone", "--quiet", cloneURL, dir)
	git(name, dir, "config", "user.email", "spike@example.invalid")
	git(name, dir, "config", "user.name", "patvault spike")

	parent := git(name, dir, "rev-parse", "HEAD")
	git(name, dir, "commit", "--quiet", "--allow-empty", "-m", "patvault relay push spike")
	newOID := git(name, dir, "rev-parse", "HEAD")

	// Pack exactly the objects in newOID that are not already in parent: one
	// commit object. The server already has everything else.
	packCmd := exec.Command("git", "pack-objects", "--revs", "--stdout")
	packCmd.Dir = dir
	packCmd.Stdin = strings.NewReader("^" + parent + "\n" + newOID + "\n")
	var packBuf, packErr bytes.Buffer
	packCmd.Stdout = &packBuf
	packCmd.Stderr = &packErr
	if err := packCmd.Run(); err != nil {
		fail(name, "pack-objects: %v (%s)", err, packErr.String())
	}
	pack := packBuf.Bytes()
	if len(pack) == 0 {
		fail(name, "pack-objects produced an empty pack")
	}

	ref := fmt.Sprintf("refs/heads/spike-push-%d", time.Now().Unix())
	report := receivePack(name, base, token, zeroOID+" "+newOID+" "+ref, pack)

	if len(report) == 0 {
		fail(name, "empty report-status")
	}
	if report[0] != "unpack ok" {
		fail(name, "report-status[0] = %q, want %q (full report: %v)",
			report[0], "unpack ok", report)
	}
	wantOK := "ok " + ref
	if !slices.Contains(report, wantOK) {
		fail(name, "report-status has no %q (full report: %v)", wantOK, report)
	}
	pass(name)
	fmt.Printf("      pushed        = %s -> %s\n", newOID[:12], ref)
	fmt.Printf("      pack size     = %d bytes\n", len(pack))
	fmt.Printf("      report-status = %v\n", report)

	// Clean up: delete the scratch ref. A delete-only request carries no pack,
	// which is worth recording on its own — the bridge must not assume a pack
	// always follows the commands.
	const delName = "push delete-ref round-trip (no pack)"
	delReport := receivePack(delName, base, token, newOID+" "+zeroOID+" "+ref, nil)
	if len(delReport) == 0 || delReport[0] != "unpack ok" {
		fail(delName, "report-status = %v, want leading %q", delReport, "unpack ok")
	}
	if !slices.Contains(delReport, wantOK) {
		fail(delName, "report-status has no %q (full report: %v)", wantOK, delReport)
	}
	pass(delName)
	fmt.Printf("      deleted       = %s\n", ref)
	fmt.Printf("      report-status = %v\n", delReport)
}
