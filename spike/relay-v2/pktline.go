package main

import (
	"fmt"
	"io"
	"strconv"
)

// pkt-line kinds returned by readPktLine.
const (
	pktData  = iota // a normal data packet
	pktFlush        // flush-pkt: "0000"
	pktDelim        // delim-pkt: "0001"
)

// writePktLine writes payload as one pkt-line: a 4-byte hex length prefix
// covering the whole line (prefix + payload) followed by the payload.
func writePktLine(w io.Writer, payload string) error {
	n := len(payload) + 4
	if n > 65520 {
		return fmt.Errorf("pkt-line payload too long: %d bytes", len(payload))
	}
	_, err := fmt.Fprintf(w, "%04x%s", n, payload)
	return err
}

// writeFlush writes a flush-pkt ("0000").
func writeFlush(w io.Writer) error {
	_, err := io.WriteString(w, "0000")
	return err
}

// writeDelim writes a delim-pkt ("0001").
func writeDelim(w io.Writer) error {
	_, err := io.WriteString(w, "0001")
	return err
}

// readPktLine reads one pkt-line. For flush/delim packets it returns a nil
// payload with kind pktFlush/pktDelim. For data packets it returns the payload
// (length prefix stripped) with kind pktData.
func readPktLine(r io.Reader) (payload []byte, kind int, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid pkt-line length %q: %w", hdr[:], err)
	}
	switch n {
	case 0:
		return nil, pktFlush, nil
	case 1:
		return nil, pktDelim, nil
	case 2, 3:
		return nil, 0, fmt.Errorf("reserved pkt-line length %d", n)
	}
	if n > 65520 {
		return nil, 0, fmt.Errorf("pkt-line length %d exceeds maximum 65520", n)
	}
	buf := make([]byte, n-4)
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, 0, fmt.Errorf("short pkt-line body (want %d bytes): %w", n-4, err)
	}
	return buf, pktData, nil
}
