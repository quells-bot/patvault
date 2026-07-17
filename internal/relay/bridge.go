package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Bridge is the pkt-line ↔ HTTPS upstream. It is a server-side re-implementation
// of git's remote-curl: it speaks the v2 smart-HTTP protocol to GitHub, injects
// the stored PAT as HTTP Basic auth, and pumps framed pkt-lines between the SSH
// channel and HTTP bodies without interpreting them.
//
// Client and BaseURL are injected so the bridge is testable without a network:
// tests point BaseURL at an httptest.Server. Production sets BaseURL to
// "https://github.com".
type Bridge struct {
	// Client issues the upstream requests. A dedicated *http.Client with no
	// Timeout is correct: a Client.Timeout would abort large pack transfers
	// mid-stream, and cancellation is owned by the request context.
	Client *http.Client
	// BaseURL is the forge root, without a trailing slash (e.g.
	// "https://github.com"). The repo is appended as "<owner/repo>.git".
	BaseURL string
}

// Push is the receive-pack bridge. Slice 3 ships the fetch path only; push
// arrives in slice 4, where it reuses the header/pump helpers added here. Until
// then a push is refused — the error is not a *relayError, so dispatch maps it
// to the internal-fault row (server.go clientError), exactly as a nil bridge.
func (b *Bridge) Push(_ context.Context, _ Request, _ io.Reader, _ io.Writer) error {
	return errors.New("push bridge not implemented (slice 4)")
}

// Fetch runs the v2 stateless-rpc pump: the advertisement GET (banner+flush
// stripped, then forwarded), then one POST per client command, each response
// streamed back verbatim.
//
// Fail-before-first-byte is the bridge's invariant: nothing is written to out
// until the advertisement GET returns 2xx. A non-2xx advertisement is mapped to
// the spec's upstream error rows and returned before any byte reaches the
// client.
//
// The bridge is half-duplex in time (read the advertisement, write it; then
// read one command, write its response). That is what makes the aliased
// ssh.Channel-as-both-in-and-out safe: read consumes client→relay bytes, write
// produces relay→client bytes, and they never collide. See
// docs/superpowers/notes/2026-07-17-relay-slice-3-channel-aliasing.md.
func (b *Bridge) Fetch(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	if err := b.advertise(ctx, req, out); err != nil {
		return err
	}
	// The command pump is added in Task 3. Until then, after the advertisement
	// the client (in tests) sends EOF and Fetch returns cleanly.
	return b.pumpCommands(ctx, req, in, out)
}

// endpoint builds the upload-pack URL for req: "<BaseURL>/<repo>.git/<service>".
func (b *Bridge) endpoint(req Request, service string) string {
	return fmt.Sprintf("%s/%s.git/%s", trimSlash(b.BaseURL), req.Repo, service)
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// advertise does the GET, checks 2xx before writing anything, strips the
// smart-HTTP "# service=" banner + flush that the SSH transport does not use,
// and copies the remaining v2 advertisement to out verbatim.
//
// readPacket reads exact lengths with io.ReadFull (no buffering), so consuming
// the banner and flush steals no bytes from the io.Copy that follows.
func (b *Bridge) advertise(ctx context.Context, req Request, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		b.endpoint(req, "info/refs?service=git-upload-pack"), nil)
	if err != nil {
		return fmt.Errorf("build advertise request: %w", err)
	}
	setUpstreamHeaders(httpReq, req, "application/x-git-upload-pack-advertisement")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}

	// The smart-HTTP advertisement prefixes one data pkt-line (the
	// "# service=git-upload-pack" banner) and a flush-pkt that the SSH
	// transport never sends. Strip both, then pump the rest unchanged.
	if _, kind, err := readPacket(resp.Body); err != nil || kind != pktData {
		return errInternal()
	}
	if _, kind, err := readPacket(resp.Body); err != nil || kind != pktFlush {
		return errInternal()
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy advertisement: %w", err)
	}
	return nil
}

// pumpCommands loops over the client's v2 commands: read one command up to its
// terminating flush-pkt (readCommand returns io.EOF when the client is done),
// POST it to git-upload-pack, and stream the response back to out verbatim. The
// response is never interpreted — sideband framing, section order, and pack
// bytes pass through untouched, which is what makes partial/shallow clones and
// sideband progress work for free.
//
// This is the half-duplex-in-time core: read a command, write its response,
// repeat. The bridge never writes a response while still reading a command, and
// never reads the next command while a response is in flight — so the aliased
// ssh.Channel's read and write halves never collide.
func (b *Bridge) pumpCommands(ctx context.Context, req Request, in io.Reader, out io.Writer) error {
	for {
		cmd, err := readCommand(in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read client command: %w", err)
		}
		if err := b.postCommand(ctx, req, cmd, out); err != nil {
			return err
		}
	}
}

// postCommand POSTs one command (framing intact, as readCommand returned it) to
// git-upload-pack and streams the response to out verbatim. The command body is
// bounded by its flush-pkt, so Content-Length is known and the POST is not
// chunked (chunked is only the push path's concern, in slice 4).
func (b *Bridge) postCommand(ctx context.Context, req Request, cmd []byte, out io.Writer) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.endpoint(req, "git-upload-pack"), bytes.NewReader(cmd))
	if err != nil {
		return fmt.Errorf("build command request: %w", err)
	}
	setUpstreamHeaders(httpReq, req, "application/x-git-upload-pack-request")
	httpReq.Header.Set("Accept", "application/x-git-upload-pack-result")

	resp, err := b.Client.Do(httpReq)
	if err != nil {
		return errGitHubUnreachable(0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(req.Repo, resp.StatusCode)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy command response: %w", err)
	}
	return nil
}

// setUpstreamHeaders sets the headers every upstream request carries: the PAT
// as HTTP Basic auth (the username is the conventional x-access-token
// placeholder — GitHub's Git transport takes Basic, not Bearer), the v2
// protocol marker, and the per-request content type and accept type. The
// User-Agent matches what the relay-v2 spike sent to real GitHub and had
// accepted.
func setUpstreamHeaders(req *http.Request, r Request, contentType string) {
	req.SetBasicAuth("x-access-token", r.PAT)
	req.Header.Set("Git-Protocol", gitProtocolV2)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)
	req.Header.Set("User-Agent", "git/2.43.0")
}

// classifyStatus maps a non-2xx upstream status to the spec's error table. The
// table marks this mapping as inferred rather than observed (§"Unverified
// assumptions"); slice 5 confirms each row against the real Git endpoints.
func classifyStatus(repo string, status int) *relayError {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return errGitHubAuth(repo)
	case status == http.StatusNotFound:
		return errGitHubNotFound(repo)
	case status >= 500:
		return errGitHubUnreachable(status)
	default:
		// A status outside the table (unexpected 4xx). Treat it as an
		// unreachable upstream rather than a silent success: the client gets a
		// retryable signal and the host log gets the code via refuse's cause.
		return errGitHubUnreachable(status)
	}
}