package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// sessionTimeout bounds a single captured session so a wedged client cannot
// hang the spike.
const sessionTimeout = 20 * time.Second

// capture records what one SSH session asked for, in arrival order.
type capture struct {
	Order    []string // request types as they arrived, e.g. ["env", "exec"]
	Envs     []envRequest
	Exec     string
	ExecSeen bool
	Err      error
}

// gitProtocol returns the value of the GIT_PROTOCOL env request and whether one
// was sent at all.
func (c *capture) gitProtocol() (string, bool) {
	for _, e := range c.Envs {
		if e.Name == "GIT_PROTOCOL" {
			return e.Value, true
		}
	}
	return "", false
}

// gitProtocolBeforeExec reports whether a GIT_PROTOCOL env request arrived
// before the first exec request. This is the ordering the relay depends on: it
// must know the protocol version at the moment it handles the exec, not after.
func (c *capture) gitProtocolBeforeExec() bool {
	envIdx := 0
	for _, typ := range c.Order {
		switch typ {
		case "env":
			if envIdx >= len(c.Envs) {
				return false
			}
			e := c.Envs[envIdx]
			envIdx++
			if e.Name == "GIT_PROTOCOL" {
				return true
			}
		case "exec":
			return false
		}
	}
	return false
}

// newHostKey generates an ephemeral ed25519 host key. Nothing persists it: a
// fresh key per run is fine because every client here disables host-key
// checking.
func newHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// serveOnce accepts exactly one connection, records its channel requests, and
// refuses the operation as soon as an exec arrives. It never runs git: the
// request capture is the whole point, so the client is expected to fail.
func serveOnce(ln net.Listener, hostKey ssh.Signer) *capture {
	c := &capture{}

	nConn, err := ln.Accept()
	if err != nil {
		c.Err = fmt.Errorf("accept: %w", err)
		return c
	}
	defer nConn.Close()
	if err := nConn.SetDeadline(time.Now().Add(sessionTimeout)); err != nil {
		c.Err = fmt.Errorf("set deadline: %w", err)
		return c
	}

	cfg := &ssh.ServerConfig{
		// Any key is accepted. Authorization is not what this spike tests.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	sConn, chans, globalReqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		c.Err = fmt.Errorf("handshake: %w", err)
		return c
	}
	defer sConn.Close()
	go ssh.DiscardRequests(globalReqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			c.Err = fmt.Errorf("accept channel: %w", err)
			return c
		}
		for req := range reqs {
			c.Order = append(c.Order, req.Type)
			switch req.Type {
			case "env":
				e, err := parseEnvReq(req.Payload)
				if err != nil {
					c.Err = fmt.Errorf("env payload: %w", err)
					ch.Close()
					return c
				}
				c.Envs = append(c.Envs, e)
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "exec":
				x, err := parseExecReq(req.Payload)
				if err != nil {
					c.Err = fmt.Errorf("exec payload: %w", err)
					ch.Close()
					return c
				}
				c.Exec = x.Command
				c.ExecSeen = true
				if req.WantReply {
					req.Reply(true, nil)
				}
				fmt.Fprint(ch.Stderr(), "patvault-spike: capture only, refusing\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus{Status: 1}))
				ch.Close()
				return c
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}
	return c
}
