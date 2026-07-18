package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// writePkt writes s as one pkt-line (4-byte hex length prefix + payload). Test
// helper only — production pumps bytes verbatim and never writes pkt-lines.
func writePkt(w io.Writer, s string) {
	fmt.Fprintf(w, "%04x%s", len(s)+4, s)
}

// writeFlush writes a flush-pkt ("0000").
func writeFlush(w io.Writer) {
	io.WriteString(w, "0000")
}

// stubAdvertisement is a real-shape v2 advertisement (the capability list git
// 2.53.0 emits), prefixed with the smart-HTTP "# service=" banner + flush that
// the SSH transport does not use and the bridge must strip.
func stubAdvertisement() []byte {
	var b strings.Builder
	writePkt(&b, "# service=git-upload-pack\n")
	writeFlush(&b)
	writePkt(&b, "version 2\n")
	writePkt(&b, "agent=git/2.53.0-Linux\n")
	writePkt(&b, "ls-refs=unborn\n")
	writePkt(&b, "fetch=shallow wait-for-done\n")
	writePkt(&b, "server-option\n")
	writePkt(&b, "object-format=sha1\n")
	writeFlush(&b)
	return []byte(b.String())
}

// advWithoutBanner is stubAdvertisement with the banner+flush removed — what the
// fetch bridge must write to out.
func advWithoutBanner() []byte {
	return stripBanner(stubAdvertisement())
}

// stripBanner drops the first two packets (the "# service=" banner data pkt and
// its flush) from a smart-HTTP advertisement, returning what the bridge forwards.
// Shared by the fetch and push advertisement assertions.
func stripBanner(full []byte) []byte {
	r := bytes.NewReader(full)
	readPacket(r) // banner
	readPacket(r) // flush
	rest, _ := io.ReadAll(r)
	return rest
}

// stubReceivePackAdvertisement is a real-shape classic (non-v2) ref advertisement
// — the ref line + NUL-separated capabilities git-receive-pack emits — prefixed
// with the smart-HTTP "# service=git-receive-pack" banner + flush the SSH
// transport does not use and the bridge must strip.
func stubReceivePackAdvertisement() []byte {
	var b strings.Builder
	writePkt(&b, "# service=git-receive-pack\n")
	writeFlush(&b)
	writePkt(&b, "caea8767d0ef709639db64552a8d5d87957301ab refs/heads/main\x00"+
		"report-status report-status-v2 delete-refs side-band-64k quiet atomic object-format=sha1\n")
	writeFlush(&b)
	return []byte(b.String())
}

// stubReq records one upstream request's headers and body.
type stubReq struct {
	auth, gitProto, accept, ctype string
	chunked                       bool
	contentLength                 int64
	body                          []byte
}

// stubUpstream is a minimal smart-HTTP upload-pack upstream. It returns canned
// bytes so the bridge's framing, header injection, and error mapping can be
// asserted without a pack. adv is the GET body; postResp is a factory called
// per POST. A non-zero status short-circuits the response with that code.
type stubUpstream struct {
	*httptest.Server
	mu         sync.Mutex
	gets       []stubReq
	posts      []stubReq
	adv        []byte
	postResp   func() io.Reader
	getStatus  int
	postStatus int
}

func newStubUpstream(t *testing.T, adv []byte, postResp func() io.Reader, getStatus, postStatus int) *stubUpstream {
	t.Helper()
	s := &stubUpstream{adv: adv, postResp: postResp, getStatus: getStatus, postStatus: postStatus}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		rec := stubReq{
			auth: r.Header.Get("Authorization"), gitProto: r.Header.Get("Git-Protocol"),
			accept: r.Header.Get("Accept"), ctype: r.Header.Get("Content-Type"),
			chunked: len(r.TransferEncoding) > 0, contentLength: r.ContentLength, body: body,
		}
		s.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "info/refs"):
			s.mu.Lock()
			s.gets = append(s.gets, rec)
			s.mu.Unlock()
			if s.getStatus != 0 {
				w.WriteHeader(s.getStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.Write(s.adv)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-upload-pack"):
			s.mu.Lock()
			s.posts = append(s.posts, rec)
			s.mu.Unlock()
			if s.postStatus != 0 {
				w.WriteHeader(s.postStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			io.Copy(w, s.postResp())
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "git-receive-pack"):
			s.mu.Lock()
			s.posts = append(s.posts, rec)
			s.mu.Unlock()
			if s.postStatus != 0 {
				w.WriteHeader(s.postStatus)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			io.Copy(w, s.postResp())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

func (s *stubUpstream) recordedGets() []stubReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubReq(nil), s.gets...)
}
func (s *stubUpstream) recordedPosts() []stubReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubReq(nil), s.posts...)
}

// basicAuth returns the decoded "user:pass" for an Authorization header, or "".
func basicAuth(h string) string {
	if !strings.HasPrefix(h, "Basic ") {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return ""
	}
	return string(b)
}

func TestFetchStripsServiceBannerAndForwardsAdvertisement(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(), func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if got := out.Bytes(); !bytes.Equal(got, advWithoutBanner()) {
		t.Errorf("out =\n%q\nwant advertisement without banner:\n%q", got, advWithoutBanner())
	}
	if bytes.Contains(out.Bytes(), []byte("# service=")) {
		t.Errorf("out still contains the # service= banner:\n%q", out.Bytes())
	}
	if len(stub.recordedGets()) != 1 {
		t.Errorf("recorded %d GETs, want 1", len(stub.recordedGets()))
	}
}

func TestFetchInjectsUpstreamHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(), func() io.Reader { return bytes.NewReader([]byte("resp")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	// in is EOF, so only the advertisement GET happens (the command pump lands
	// in Task 3). Assert the GET headers here; the POST headers are asserted in
	// Task 3's TestFetchInjectsPostHeaders.
	var out bytes.Buffer
	_ = b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, strings.NewReader(""), &out)

	gets := stub.recordedGets()
	if len(gets) != 1 {
		t.Fatalf("recorded %d GETs, want 1", len(gets))
	}
	g := gets[0]
	if got := basicAuth(g.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("GET Authorization = %q, want Basic x-access-token:ghp_secret", g.auth)
	}
	if g.gitProto != "version=2" {
		t.Errorf("GET Git-Protocol = %q, want version=2", g.gitProto)
	}
	if g.accept != "application/x-git-upload-pack-advertisement" {
		t.Errorf("GET Accept = %q, want advertisement", g.accept)
	}
}

func TestFetchFailBeforeFirstByteOn500(t *testing.T) {
	stub := newStubUpstream(t, nil, nil, http.StatusInternalServerError, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0 (fail-before-first-byte): %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(500)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("Fetch returned %v, want a *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("Fetch error = %v (retryable %v), want %v (retryable true)", re, re.Retryable(), want)
	}
}

func TestFetchMapsUpstreamStatusToErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   *relayError
	}{
		{"401 maps to auth", http.StatusUnauthorized, errGitHubAuth("owner/repo")},
		{"403 maps to auth", http.StatusForbidden, errGitHubAuth("owner/repo")},
		{"404 maps to not-found", http.StatusNotFound, errGitHubNotFound("owner/repo")},
		{"502 maps to unreachable", http.StatusBadGateway, errGitHubUnreachable(502)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubUpstream(t, nil, nil, tc.status, 0)
			b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}
			err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), io.Discard)
			var re *relayError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want *relayError", err)
			}
			if re.Error() != tc.want.Error() || re.Retryable() != tc.want.Retryable() {
				t.Errorf("got %q (retryable %v), want %q (retryable %v)", re, re.Retryable(), tc.want, tc.want.Retryable())
			}
		})
	}
}

func TestFetchMapsNetworkErrorToUnreachable(t *testing.T) {
	// Point the bridge at a closed port to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}

	var out bytes.Buffer
	err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0: %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(0)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("got %q, want %q", re, want)
	}
}

func TestPushStripsServiceBannerAndForwardsAdvertisement(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("Push returned %v", err)
	}
	want := stripBanner(stubReceivePackAdvertisement())
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant advertisement without banner:\n%q", got, want)
	}
	if bytes.Contains(out.Bytes(), []byte("# service=")) {
		t.Errorf("out still contains the # service= banner:\n%q", out.Bytes())
	}
	if len(stub.recordedGets()) != 1 {
		t.Errorf("recorded %d GETs, want 1", len(stub.recordedGets()))
	}
}

func TestPushAdvertisementInjectsHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(nil) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	gets := stub.recordedGets()
	if len(gets) != 1 {
		t.Fatalf("recorded %d GETs, want 1", len(gets))
	}
	g := gets[0]
	if got := basicAuth(g.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("GET Authorization = %q, want Basic x-access-token:ghp_secret", g.auth)
	}
	if g.accept != "application/x-git-receive-pack-advertisement" {
		t.Errorf("GET Accept = %q, want receive-pack advertisement", g.accept)
	}
}

func TestPushFailBeforeFirstByteOn500(t *testing.T) {
	stub := newStubUpstream(t, nil, nil, http.StatusInternalServerError, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Errorf("out = %d bytes, want 0 (fail-before-first-byte): %q", out.Len(), out.Bytes())
	}
	want := errGitHubUnreachable(500)
	var re *relayError
	if !errors.As(err, &re) {
		t.Fatalf("Push returned %v, want a *relayError", err)
	}
	if re.Error() != want.Error() || !re.Retryable() {
		t.Errorf("Push error = %v (retryable %v), want %v (retryable true)", re, re.Retryable(), want)
	}
}

func TestPushAdvertisementMapsStatusToErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   *relayError
	}{
		{"401 maps to auth", http.StatusUnauthorized, errGitHubAuth("owner/repo")},
		{"403 maps to auth", http.StatusForbidden, errGitHubAuth("owner/repo")},
		{"404 maps to not-found", http.StatusNotFound, errGitHubNotFound("owner/repo")},
		{"503 maps to unreachable", http.StatusServiceUnavailable, errGitHubUnreachable(503)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubUpstream(t, nil, nil, tc.status, 0)
			b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}
			err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, strings.NewReader(""), io.Discard)
			var re *relayError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want *relayError", err)
			}
			if re.Error() != tc.want.Error() || re.Retryable() != tc.want.Retryable() {
				t.Errorf("got %q (retryable %v), want %q (retryable %v)", re, re.Retryable(), tc.want, tc.want.Retryable())
			}
		})
	}
}

// A hand-rolled v2 ls-refs command, exactly the bytes a real git client sends:
// "command=ls-refs\n", "object-format=sha1\n", a delim-pkt, "ref-prefix HEAD\n",
// a flush-pkt. readCommand returns these bytes verbatim (framing intact) for
// the bridge to POST.
func lsRefsCommand() []byte {
	var b strings.Builder
	writePkt(&b, "command=ls-refs\n")
	writePkt(&b, "object-format=sha1\n")
	io.WriteString(&b, "0001") // delim-pkt
	writePkt(&b, "ref-prefix HEAD\n")
	writeFlush(&b)
	return []byte(b.String())
}

func fetchCommand() []byte {
	var b strings.Builder
	writePkt(&b, "command=fetch\n")
	writePkt(&b, "object-format=sha1\n")
	io.WriteString(&b, "0001")
	writePkt(&b, "no-progress\n")
	writePkt(&b, "want 0000000000000000000000000000000000000000\n")
	writePkt(&b, "done\n")
	writeFlush(&b)
	return []byte(b.String())
}

func TestFetchPumpsCommandsVerbatimAndInOrder(t *testing.T) {
	// Each POST returns a distinct canned response; assert they reach out in
	// order, after the advertisement, byte-for-byte.
	calls := 0
	responses := [][]byte{[]byte("LS-REFS-RESPONSE"), []byte("FETCH-RESPONSE")}
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { r := responses[calls]; calls++; return bytes.NewReader(r) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	// in = ls-refs command, then fetch command, then EOF.
	in := bytes.NewReader(append(lsRefsCommand(), fetchCommand()...))
	var out bytes.Buffer
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, in, &out); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}

	want := append(advWithoutBanner(), append(responses[0], responses[1]...)...)
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant\n%q", got, want)
	}

	posts := stub.recordedPosts()
	if len(posts) != 2 {
		t.Fatalf("recorded %d POSTs, want 2", len(posts))
	}
	if !bytes.Equal(posts[0].body, lsRefsCommand()) {
		t.Errorf("POST 0 body = %q, want the ls-refs command", posts[0].body)
	}
	if !bytes.Equal(posts[1].body, fetchCommand()) {
		t.Errorf("POST 1 body = %q, want the fetch command", posts[1].body)
	}
}

func TestFetchInjectsPostHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("r")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	in := bytes.NewReader(lsRefsCommand())
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, in, io.Discard); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	p := posts[0]
	if got := basicAuth(p.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("POST Authorization = %q, want Basic x-access-token:ghp_secret", p.auth)
	}
	if p.gitProto != "version=2" {
		t.Errorf("POST Git-Protocol = %q, want version=2", p.gitProto)
	}
	if p.ctype != "application/x-git-upload-pack-request" {
		t.Errorf("POST Content-Type = %q, want request", p.ctype)
	}
	if p.accept != "application/x-git-upload-pack-result" {
		t.Errorf("POST Accept = %q, want result", p.accept)
	}
}

// The channel-aliasing note's pin: the bridge must never echo the client's own
// command bytes back to out (io.Copy(out, in) would). Assert the command bytes
// the client sent do not appear in out — only the advertisement and responses do.
func TestFetchDoesNotLoopbackClientBytes(t *testing.T) {
	stub := newStubUpstream(t, stubAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("RESP")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	cmd := lsRefsCommand()
	in := bytes.NewReader(cmd)
	var out bytes.Buffer
	if err := b.Fetch(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, in, &out); err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if bytes.Contains(out.Bytes(), cmd) {
		t.Errorf("client command bytes were echoed back to out (loopback):\nout=%q", out.Bytes())
	}
	if bytes.Contains(out.Bytes(), []byte("command=ls-refs")) {
		t.Errorf("command text leaked into out:\n%q", out.Bytes())
	}
}

// Stream, never buffer: the bridge must write advertisement bytes to out as they
// arrive, not hold the whole body until EOF. The GET handler writes
// banner+flush+FIRST, flushes, then waits for the bridge to deliver FIRST to out
// before ending the body. A streaming bridge closes the signal promptly; a
// buffering bridge holds FIRST until EOF, which never arrives while it waits —
// the 2s timeout distinguishes them, deterministically.
func TestFetchStreamsAdvertisementWithoutBuffering(t *testing.T) {
	first := []byte("FIRST-CHUNK")
	bridgeWrote := make(chan struct{})
	streamed := make(chan bool, 1)

	out := &signalingWriter{firstWritten: bridgeWrote}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePkt(w, "# service=git-upload-pack\n")
		writeFlush(w)
		w.Write(first)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-bridgeWrote:
			streamed <- true
		case <-time.After(2 * time.Second):
			streamed <- false
		}
	}))
	t.Cleanup(srv.Close)

	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}
	done := make(chan error, 1)
	go func() {
		done <- b.Fetch(context.Background(), Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), out)
	}()
	if err := <-done; err != nil {
		t.Fatalf("Fetch returned %v", err)
	}
	if !<-streamed {
		t.Error("FIRST did not reach out before the body EOF — bridge is buffering, not streaming")
	}
	if !bytes.Contains(out.bytes, first) {
		t.Errorf("out missing FIRST: %q", out.bytes)
	}
}

// signalingWriter records all bytes written and closes firstWritten on the first
// Write — so the streaming test can observe the bridge delivering the first
// chunk before the response body is complete.
type signalingWriter struct {
	bytes        []byte
	firstWritten chan struct{}
	once         sync.Once
}

func (w *signalingWriter) Write(p []byte) (int, error) {
	w.bytes = append(w.bytes, p...)
	w.once.Do(func() { close(w.firstWritten) })
	return len(p), nil
}

func TestFetchRespectsContextCancellation(t *testing.T) {
	// A GET that never responds: the bridge must return when ctx is cancelled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	b := &Bridge{Client: srv.Client(), BaseURL: srv.URL}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := b.Fetch(ctx, Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Error("Fetch returned nil; want an error after ctx cancellation")
	}
}

// pushCommands is a hand-rolled receive-pack request body: one ref-update command
// pkt-line (old-oid new-oid ref, NUL, capabilities), a flush-pkt, then a stand-in
// "pack" (the bridge never parses it, so opaque bytes are faithful — git sends a
// raw, un-pkt-line-framed pack here). withPack=false is the delete-only shape:
// commands + flush and nothing after.
func pushCommands(withPack bool) []byte {
	var b strings.Builder
	writePkt(&b, "0000000000000000000000000000000000000000 "+
		"bf13b4419cf93eabd9b18d4ad9c2210a9268fdef refs/heads/main\x00"+
		"report-status side-band-64k object-format=sha1 agent=git/2.53.0-Linux")
	writeFlush(&b)
	out := []byte(b.String())
	if withPack {
		out = append(out, []byte("PACK\x00\x00\x00\x02rawpackbytes-not-pkt-framed")...)
	}
	return out
}

// sidebandReportStatus is a report-status riding sideband channel 1 (\x01), the
// framing GitHub uses when the client requested side-band-64k. It carries an `ng`
// rejection line — the path the live push spike never exercised. The bridge must
// reproduce these bytes exactly; reframing them breaks the client with "bad band".
func sidebandReportStatus() []byte {
	var status strings.Builder
	writePkt(&status, "unpack ok\n")
	writePkt(&status, "ng refs/heads/main non-fast-forward\n")
	writeFlush(&status)
	var b strings.Builder
	writePkt(&b, "\x01"+status.String()) // one band-1 chunk carrying the status
	writeFlush(&b)
	return []byte(b.String())
}

func TestPushStreamsClientBodyToUpstreamAndReportStatusBack(t *testing.T) {
	report := []byte("000eunpack ok\n0019ok refs/heads/main\n0000")
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(true)
	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}

	// out = advertisement (banner stripped) + report-status, verbatim.
	want := append(stripBanner(stubReceivePackAdvertisement()), report...)
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("out =\n%q\nwant\n%q", got, want)
	}
	// The upstream received the client's commands+pack byte-for-byte.
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !bytes.Equal(posts[0].body, body) {
		t.Errorf("POST body = %q, want the client's commands+pack %q", posts[0].body, body)
	}
}

func TestPushSendsChunkedRequestBody(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(pushCommands(true)), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !posts[0].chunked {
		t.Error("receive-pack POST was not chunked; the body length is unknown up front and must go out chunked")
	}
}

func TestPushInjectsPostHeaders(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_secret"}, bytes.NewReader(pushCommands(true)), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	p := stub.recordedPosts()[0]
	if got := basicAuth(p.auth); got != "x-access-token:ghp_secret" {
		t.Errorf("POST Authorization = %q, want Basic x-access-token:ghp_secret", p.auth)
	}
	if p.ctype != "application/x-git-receive-pack-request" {
		t.Errorf("POST Content-Type = %q, want receive-pack-request", p.ctype)
	}
	if p.accept != "application/x-git-receive-pack-result" {
		t.Errorf("POST Accept = %q, want receive-pack-result", p.accept)
	}
}

// The report-status may be sideband-framed and may carry `ng` rejection lines.
// The bridge pumps it byte-for-byte; a single reframed byte breaks the client.
func TestPushForwardsSidebandReportStatusVerbatim(t *testing.T) {
	report := sidebandReportStatus()
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(pushCommands(true)), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	tail := out.Bytes()[len(stripBanner(stubReceivePackAdvertisement())):]
	if !bytes.Equal(tail, report) {
		t.Errorf("report-status not forwarded verbatim:\ngot  %q\nwant %q", tail, report)
	}
	if !bytes.Contains(tail, []byte{0x01}) {
		t.Error("sideband channel marker (\\x01) was stripped — the bridge reframed the reply")
	}
	if !bytes.Contains(tail, []byte("ng refs/heads/main")) {
		t.Error("ng rejection line did not survive pass-through")
	}
}

// A delete-only push sends commands + flush and no pack. It is the same code
// path: the body ends at the client's EOF regardless of whether a pack followed.
func TestPushDeleteOnlyHasNoPack(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(false) // commands + flush, no pack
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), io.Discard); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	posts := stub.recordedPosts()
	if len(posts) != 1 {
		t.Fatalf("recorded %d POSTs, want 1", len(posts))
	}
	if !bytes.Equal(posts[0].body, body) {
		t.Errorf("delete-only POST body = %q, want commands+flush %q", posts[0].body, body)
	}
}

// The channel-aliasing pin for push: the bridge must never echo the client's
// commands+pack back to out. Only the advertisement and the report-status appear.
func TestPushDoesNotLoopbackClientBytes(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := pushCommands(true)
	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("rawpackbytes-not-pkt-framed")) {
		t.Errorf("client pack bytes were echoed back to out (loopback):\nout=%q", out.Bytes())
	}
	if bytes.Contains(out.Bytes(), []byte("refs/heads/main\x00report-status side-band-64k")) {
		t.Errorf("client command bytes leaked into out:\n%q", out.Bytes())
	}
}

// countingChannel is an io.ReadWriteCloser that records Close() calls, standing
// in for the ssh.Channel Push receives in production, where in and out are the
// SAME channel. It guards the invariant that pushPack never lets net/http close
// the client channel: pushPack builds the request body from a *bytes.Reader or an
// io.MultiReader (neither an io.Closer), so net/http cannot reach ch.Close(). If a
// future change passed the channel to net/http as an io.ReadCloser instead, the
// transport would Close() it after the send — tearing down the aliased channel
// before the report-status is written. The *bytes.Reader the other push tests use
// is not an io.Closer, so it cannot catch that regression; only a real Closer can.
type countingChannel struct {
	io.Reader
	closeCalls int
}

func (c *countingChannel) Write(p []byte) (int, error) { return len(p), nil }
func (c *countingChannel) Close() error                { c.closeCalls++; return nil }

func TestPushDoesNotCloseTheClientChannel(t *testing.T) {
	report := []byte("000eunpack ok\n0000")
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	ch := &countingChannel{Reader: bytes.NewReader(pushCommands(true))}
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, ch, ch); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	if ch.closeCalls != 0 {
		t.Errorf("Push let net/http close the client channel %d time(s); in production that closes the aliased ssh.Channel before the report-status is written", ch.closeCalls)
	}
}

// deleteCommands is a real delete-only receive-pack command list: one ref-update
// whose new-oid is all zeros (a deletion), then a flush-pkt, and NO packfile.
// The old-oid is a real sha; only new-oid = zeros marks the delete.
func deleteCommands() []byte {
	var b strings.Builder
	writePkt(&b, "bf13b4419cf93eabd9b18d4ad9c2210a9268fdef "+
		"0000000000000000000000000000000000000000 refs/heads/main\x00"+
		"report-status side-band-64k object-format=sha1 agent=git/2.53.0-Linux")
	writeFlush(&b)
	return []byte(b.String())
}

// haltAfter yields data once, then blocks on every later Read until the test
// ends — modeling a git client that sends a delete-only command list and does
// NOT half-close its write side (the real 408-hang). A correct pushPack reads
// only through the flush and never touches the blocked tail.
type haltAfter struct {
	data []byte
	halt chan struct{}
}

func (r *haltAfter) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	<-r.halt
	return 0, io.EOF
}

// A delete-only push sends no packfile, so the bridge must send the buffered
// command list with a known Content-Length (not chunked) rather than wait for a
// client EOF that never comes.
func TestPushDeleteOnlySendsBufferedBodyWithContentLength(t *testing.T) {
	report := []byte("000eunpack ok\n0019ok refs/heads/main\n0000")
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader(report) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	body := deleteCommands()
	var out bytes.Buffer
	if err := b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Push returned %v", err)
	}
	p := stub.recordedPosts()[0]
	if p.chunked {
		t.Error("delete-only push was chunked; it must be sent with a known Content-Length")
	}
	if p.contentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d (buffered command list)", p.contentLength, len(body))
	}
	if !bytes.Equal(p.body, body) {
		t.Errorf("POST body = %q, want the delete command list %q", p.body, body)
	}
	want := append(stripBanner(stubReceivePackAdvertisement()), report...)
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("out = %q, want advertisement + report-status", out.Bytes())
	}
}

// The 408-hang regression guard: a delete-only push must complete even when the
// client never EOFs its write side. With the pre-fix code (passing `in` straight
// to net/http) this deadlocks; the fix reads only through the flush.
func TestPushDeleteOnlyDoesNotWaitForClientEOF(t *testing.T) {
	stub := newStubUpstream(t, stubReceivePackAdvertisement(),
		func() io.Reader { return bytes.NewReader([]byte("000eunpack ok\n0000")) }, 0, 0)
	b := &Bridge{Client: stub.Client(), BaseURL: stub.URL}

	halt := make(chan struct{})
	defer close(halt)
	in := &haltAfter{data: deleteCommands(), halt: halt}

	done := make(chan error, 1)
	go func() {
		done <- b.Push(context.Background(), Request{Repo: "owner/repo", PAT: "ghp_x"}, in, io.Discard)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Push returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Push blocked waiting for a client EOF on a delete-only push (the 408-hang bug)")
	}
}

func TestAllDeletions(t *testing.T) {
	create := func() []byte { // a non-delete command (new-oid non-zero), no pack in this fixture
		var b strings.Builder
		writePkt(&b, "0000000000000000000000000000000000000000 "+
			"bf13b4419cf93eabd9b18d4ad9c2210a9268fdef refs/heads/main\x00report-status")
		writeFlush(&b)
		return []byte(b.String())
	}
	mixed := func() []byte {
		var b strings.Builder
		writePkt(&b, "aaaa000000000000000000000000000000000000 "+
			"0000000000000000000000000000000000000000 refs/heads/gone\x00report-status")
		writePkt(&b, "aaaa000000000000000000000000000000000000 "+
			"bf13b4419cf93eabd9b18d4ad9c2210a9268fdef refs/heads/main")
		writeFlush(&b)
		return []byte(b.String())
	}
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"single delete", deleteCommands(), true},
		{"single create", create(), false},
		{"delete + create mixed", mixed(), false},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := allDeletions(tc.in); got != tc.want {
				t.Errorf("allDeletions() = %v, want %v", got, tc.want)
			}
		})
	}
}
