package relay

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadPacketData(t *testing.T) {
	r := strings.NewReader("0014command=ls-refs\n")
	payload, kind, err := readPacket(r)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if kind != pktData {
		t.Errorf("kind = %d, want pktData", kind)
	}
	if string(payload) != "command=ls-refs\n" {
		t.Errorf("payload = %q, want %q", payload, "command=ls-refs\n")
	}
}

func TestReadPacketFlushAndDelim(t *testing.T) {
	r := strings.NewReader("00000001")

	if _, kind, err := readPacket(r); err != nil || kind != pktFlush {
		t.Fatalf("first packet: kind=%d err=%v, want pktFlush", kind, err)
	}
	if _, kind, err := readPacket(r); err != nil || kind != pktDelim {
		t.Fatalf("second packet: kind=%d err=%v, want pktDelim", kind, err)
	}
}

func TestReadPacketSequence(t *testing.T) {
	// One ls-refs command as spike/relay-v2 framed it: command, capabilities,
	// delim, arguments, flush.
	r := strings.NewReader(
		"0014command=ls-refs\n" +
			"0017object-format=sha1\n" +
			"0001" +
			"0009peel\n" +
			"0000")

	want := []struct {
		payload string
		kind    int
	}{
		{"command=ls-refs\n", pktData},
		{"object-format=sha1\n", pktData},
		{"", pktDelim},
		{"peel\n", pktData},
		{"", pktFlush},
	}
	for i, w := range want {
		payload, kind, err := readPacket(r)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if kind != w.kind {
			t.Errorf("packet %d: kind = %d, want %d", i, kind, w.kind)
		}
		if string(payload) != w.payload {
			t.Errorf("packet %d: payload = %q, want %q", i, payload, w.payload)
		}
	}
	if _, _, err := readPacket(r); !errors.Is(err, io.EOF) {
		t.Errorf("after last packet: err = %v, want io.EOF", err)
	}
}

// A bare io.EOF at a packet boundary is the "peer is done" signal readCommand
// keys on; it must not arrive wrapped.
func TestReadPacketCleanEOF(t *testing.T) {
	_, _, err := readPacket(strings.NewReader(""))
	if err != io.EOF {
		t.Errorf("err = %v, want exactly io.EOF", err)
	}
}

func TestReadPacketErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"non-hex length", "zzzz"},
		{"reserved length 2", "0002"},
		{"reserved length 3", "0003"},
		{"truncated prefix", "00"},
		{"truncated body", "0014command"},
		{"length over maximum", "fff1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readPacket(strings.NewReader(tc.in)); err == nil {
				t.Errorf("readPacket(%q) = nil error, want error", tc.in)
			}
		})
	}
}

// A truncated stream must never masquerade as a clean end of stream.
func TestReadPacketTruncatedIsNotEOF(t *testing.T) {
	_, _, err := readPacket(bytes.NewReader([]byte("00")))
	if errors.Is(err, io.EOF) {
		t.Errorf("truncated prefix reported as EOF: %v", err)
	}
}

func TestReadCommandRoundTripsBytesVerbatim(t *testing.T) {
	// The ls-refs command spike/relay-v2/main.go sends, byte for byte. The
	// bridge forwards this as an HTTP body unmodified, so the returned bytes
	// must equal the input exactly — framing, interior delim, and all.
	const cmd = "0014command=ls-refs\n" +
		"0017object-format=sha1\n" +
		"0001" +
		"0009peel\n" +
		"000csymrefs\n" +
		"0014ref-prefix HEAD\n" +
		"0000"

	got, err := readCommand(strings.NewReader(cmd))
	if err != nil {
		t.Fatalf("readCommand: %v", err)
	}
	if string(got) != cmd {
		t.Errorf("readCommand returned\n%q\nwant\n%q", got, cmd)
	}
}

// gitprotocol-v2's grammar is "request = empty-request | command-request",
// where "empty-request = flush-pkt": a client may send a lone flush to say no
// more requests are coming. That is a termination, not a command — forwarding
// "0000" upstream as a request body would POST garbage to GitHub.
func TestReadCommandEmptyRequestIsEOF(t *testing.T) {
	got, err := readCommand(strings.NewReader("0000"))
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if len(got) != 0 {
		t.Errorf("returned %q, want no bytes", got)
	}
}

// The empty-request arrives after a real command, on the same channel: the
// client asks for what it wants, then says it is done.
func TestReadCommandEmptyRequestAfterCommand(t *testing.T) {
	const cmd = "0014command=ls-refs\n0000"
	r := strings.NewReader(cmd + "0000")

	got, err := readCommand(r)
	if err != nil {
		t.Fatalf("first readCommand: %v", err)
	}
	if string(got) != cmd {
		t.Errorf("first command = %q, want %q", got, cmd)
	}

	if _, err := readCommand(r); !errors.Is(err, io.EOF) {
		t.Errorf("empty request: err = %v, want io.EOF", err)
	}
}

// A delim-pkt is interior framing, never a terminator: a command that opened
// with one would still be waiting for its flush.
func TestReadCommandLeadingDelimIsNotEmptyRequest(t *testing.T) {
	if _, err := readCommand(strings.NewReader("0001")); errors.Is(err, io.EOF) {
		t.Errorf("leading delim then EOF: err = %v, want a truncation error", err)
	}
}

func TestReadCommandStopsAtFirstFlush(t *testing.T) {
	const first = "0014command=ls-refs\n0000"
	const second = "0012command=fetch\n0000"
	r := strings.NewReader(first + second)

	got, err := readCommand(r)
	if err != nil {
		t.Fatalf("first readCommand: %v", err)
	}
	if string(got) != first {
		t.Errorf("first command = %q, want %q", got, first)
	}

	got, err = readCommand(r)
	if err != nil {
		t.Fatalf("second readCommand: %v", err)
	}
	if string(got) != second {
		t.Errorf("second command = %q, want %q", got, second)
	}

	if _, err := readCommand(r); !errors.Is(err, io.EOF) {
		t.Errorf("third readCommand: err = %v, want io.EOF", err)
	}
}

// The pump loop's termination condition: no more commands is io.EOF, not an
// error and not an empty command.
func TestReadCommandCleanEOF(t *testing.T) {
	got, err := readCommand(strings.NewReader(""))
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if len(got) != 0 {
		t.Errorf("returned %q, want no bytes", got)
	}
}

func TestReadCommandTruncated(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"whole packet then EOF, no flush", "0014command=ls-refs\n", io.ErrUnexpectedEOF},
		{"packet cut mid-body", "0014command", nil}, // some error, not EOF
		{"invalid length", "0014command=ls-refs\nzzzz", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readCommand(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("readCommand(%q) = nil error, want error", tc.in)
			}
			if errors.Is(err, io.EOF) {
				t.Errorf("truncated input reported as clean EOF: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
