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