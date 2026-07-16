package main

import (
	"bytes"
	"testing"
)

func TestWritePktLineKnownVector(t *testing.T) {
	var buf bytes.Buffer
	if err := writePktLine(&buf, "hello\n"); err != nil {
		t.Fatal(err)
	}
	// len("hello\n")=6, +4 prefix = 10 = 0x0a
	if got, want := buf.String(), "000ahello\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriteDoneVector(t *testing.T) {
	var buf bytes.Buffer
	if err := writePktLine(&buf, "done\n"); err != nil {
		t.Fatal(err)
	}
	// len("done\n")=5, +4 = 9 = 0x09
	if got, want := buf.String(), "0009done\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFlushAndDelim(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFlush(&buf); err != nil {
		t.Fatal(err)
	}
	if err := writeDelim(&buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "00000001"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writePktLine(&buf, "command=ls-refs\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeDelim(&buf); err != nil {
		t.Fatal(err)
	}
	if err := writePktLine(&buf, "peel\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFlush(&buf); err != nil {
		t.Fatal(err)
	}

	p, kind, err := readPktLine(&buf)
	if err != nil || kind != pktData || string(p) != "command=ls-refs\n" {
		t.Fatalf("pkt1: p=%q kind=%d err=%v", p, kind, err)
	}
	if _, kind, err = readPktLine(&buf); err != nil || kind != pktDelim {
		t.Fatalf("pkt2: kind=%d err=%v", kind, err)
	}
	p, kind, err = readPktLine(&buf)
	if err != nil || kind != pktData || string(p) != "peel\n" {
		t.Fatalf("pkt3: p=%q kind=%d err=%v", p, kind, err)
	}
	if _, kind, err = readPktLine(&buf); err != nil || kind != pktFlush {
		t.Fatalf("pkt4: kind=%d err=%v", kind, err)
	}
}

func TestReadInvalidLength(t *testing.T) {
	if _, _, err := readPktLine(bytes.NewReader([]byte("zzzz"))); err == nil {
		t.Fatal("expected error on invalid hex length")
	}
}
