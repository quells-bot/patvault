package main

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseEnvReq(t *testing.T) {
	want := envRequest{Name: "GIT_PROTOCOL", Value: "version=2"}
	payload := ssh.Marshal(want)
	got, err := parseEnvReq(payload)
	if err != nil {
		t.Fatalf("parseEnvReq(%x) = _, %v", payload, err)
	}
	if got != want {
		t.Errorf("parseEnvReq(%x) = %+v, want %+v", payload, got, want)
	}
}

func TestParseEnvReqRejectsTruncated(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02}
	_, err := parseEnvReq(payload)
	if err == nil {
		t.Fatal("parseEnvReq on truncated payload: expected error, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestParseExecReq(t *testing.T) {
	want := execRequest{Command: "git-upload-pack"}
	payload := ssh.Marshal(want)
	got, err := parseExecReq(payload)
	if err != nil {
		t.Fatalf("parseExecReq(%x) = _, %v", payload, err)
	}
	if got != want {
		t.Errorf("parseExecReq(%x) = %+v, want %+v", payload, got, want)
	}
}

func TestParseExecReqRejectsTruncated(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02}
	_, err := parseExecReq(payload)
	if err == nil {
		t.Fatal("parseExecReq on truncated payload: expected error, got nil")
	}
	t.Logf("got expected error: %v", err)
}
