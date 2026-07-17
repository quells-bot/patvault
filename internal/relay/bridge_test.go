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
// bridge must write to out.
func advWithoutBanner() []byte {
	full := stubAdvertisement()
	// Drop the first two packets (banner data + flush) by parsing with readPacket.
	r := bytes.NewReader(full)
	readPacket(r) // banner
	readPacket(r) // flush
	rest, _ := io.ReadAll(r)
	return rest
}

// stubReq records one upstream request's headers and body.
type stubReq struct {
	auth, gitProto, accept, ctype string
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
			accept: r.Header.Get("Accept"), ctype: r.Header.Get("Content-Type"), body: body,
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

func TestPushReturnsErrorUntilSlice4(t *testing.T) {
	b := &Bridge{Client: &http.Client{}, BaseURL: "stub"}
	err := b.Push(context.Background(), Request{Repo: "o/r", PAT: "p"}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("Push returned nil; slice 3 must refuse pushes")
	}
	// The error must NOT be a *relayError, so dispatch maps it to errInternal
	// (clientError in server.go), matching slice 2's nil-bridge behavior.
	var re *relayError
	if errors.As(err, &re) {
		t.Errorf("Push returned a *relayError %v; want a plain error dispatch maps to internal", err)
	}
}
