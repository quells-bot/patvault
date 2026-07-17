// Package relay implements patvault's credential-injecting git transport
// relay: an SSH front door for the agent's git, bridged to GitHub over HTTPS
// with a stored PAT injected upstream.
package relay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// pkt-line kinds returned by readPacket.
const (
	pktData  = iota // a normal data packet
	pktFlush        // flush-pkt: "0000"
	pktDelim        // delim-pkt: "0001"
)

// maxPktLine is the largest a pkt-line may be, 4-byte length prefix included.
const maxPktLine = 65520

// readPacket reads one pkt-line from r. Flush and delim packets return a nil
// payload with kind pktFlush or pktDelim; a data packet returns its payload
// with the length prefix stripped.
//
// A clean end of stream at a packet boundary returns a bare io.EOF. Every
// other failure — including a stream cut part-way through a packet — returns a
// wrapped error, so callers can tell "the peer is done" from "the peer is
// gone".
func readPacket(r io.Reader) (payload []byte, kind int, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, fmt.Errorf("truncated pkt-line length prefix: %w", err)
		}
		return nil, 0, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pkt-line length %q", hdr[:])
	}
	switch n {
	case 0:
		return nil, pktFlush, nil
	case 1:
		return nil, pktDelim, nil
	case 2, 3:
		return nil, 0, fmt.Errorf("reserved pkt-line length %d", n)
	}
	if n > maxPktLine {
		return nil, 0, fmt.Errorf("pkt-line length %d exceeds maximum %d", n, maxPktLine)
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, 0, fmt.Errorf("short pkt-line body (want %d bytes): %w", n-4, err)
	}
	return buf, pktData, nil
}

// readCommand reads one complete protocol-v2 command from r: every byte from
// its first pkt-line through its terminating flush-pkt, framing intact and
// unmodified, ready to be forwarded verbatim as an HTTP request body. An
// interior delim-pkt does not terminate a command.
//
// It returns io.EOF, and no bytes, for either of the two ways a client says it
// has no more commands, which is how the fetch pump's loop ends: the stream is
// already at its end, or the client sent an empty-request. gitprotocol-v2 spells
// the latter "request = empty-request | command-request" with "empty-request =
// flush-pkt" — a lone flush-pkt means "no more requests will be made", so it is
// a termination rather than a command to forward. A stream that ends after a
// whole packet but before a flush is a truncation, reported as
// io.ErrUnexpectedEOF.
func readCommand(r io.Reader) ([]byte, error) {
	// The tee is what keeps the bytes verbatim: readPacket parses from it
	// while every byte it consumes accumulates in raw, so nothing is
	// re-encoded on the way out.
	var raw bytes.Buffer
	tee := io.TeeReader(r, &raw)

	for n := 0; ; n++ {
		_, kind, err := readPacket(tee)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if raw.Len() == 0 {
					return nil, io.EOF
				}
				return nil, fmt.Errorf("stream ended before flush-pkt: %w", io.ErrUnexpectedEOF)
			}
			return nil, err
		}
		if kind == pktFlush {
			// A flush in first position closes nothing: no command was
			// opened, so this is an empty-request. A command always opens
			// with a data pkt-line ("command=…").
			if n == 0 {
				return nil, io.EOF
			}
			return raw.Bytes(), nil
		}
	}
}
