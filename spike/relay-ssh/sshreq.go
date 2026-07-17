package main

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// envRequest represents an SSH "env" channel request payload.
type envRequest struct {
	Name  string
	Value string
}

// execRequest represents an SSH "exec" channel request payload.
type execRequest struct {
	Command string
}

// exitStatus represents an SSH "exit-status" channel request payload.
type exitStatus struct {
	Status uint32
}

// parseEnvReq unmarshals an SSH "env" channel request payload.
func parseEnvReq(payload []byte) (envRequest, error) {
	var req envRequest
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return envRequest{}, fmt.Errorf("parse env request: %w", err)
	}
	return req, nil
}

// parseExecReq unmarshals an SSH "exec" channel request payload.
func parseExecReq(payload []byte) (execRequest, error) {
	var req execRequest
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return execRequest{}, fmt.Errorf("parse exec request: %w", err)
	}
	return req, nil
}
